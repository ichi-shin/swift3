# Copyright (c) 2014 OpenStack Foundation
# Copyright(c)2014 NTT corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from time import time
from datetime import datetime

from eventlet import sleep, Timeout

from swift.common import wsgi
from swift.common.swob import Request
from swift.common.daemon import Daemon
from swift.common.utils import get_logger, split_path

from swift3.acl import LifecycleConf, LifecycleConfHistory
from swift3.exception import ExpirerError
from swift3 import utils


class ObjectExpirer(Daemon):
    """
    Daemon that queries the internal hidden expiring_objects_account to
    discover objects that need to be deleted.

    :param conf: The daemon configuration.
    """

    def __init__(self, conf):
        self.conf = conf
        self.logger = get_logger(conf, log_route='swift3-object-expirer')
        self.interval = int(conf.get('interval') or 300)
        conf_path = conf.get('__file__') or \
            '/etc/swift/swift3-object-expirer.conf'
        self.swift = wsgi.loadapp(conf_path, conf)
        self.report_interval = int(conf.get('report_interval') or 300)
        self.report_first_time = self.report_last_time = time()
        self.report_objects = 0

    def report(self, final=False):
        """
        Emits a log line report of the progress so far, or the final progress
        is final=True.

        :param final: Set to True for the last report once the expiration pass
                      has completed.
        """
        if final:
            elapsed = time() - self.report_first_time
            self.logger.info('Pass completed in %ds; %d objects expired' %
                             (elapsed, self.report_objects))
        elif time() - self.report_last_time >= self.report_interval:
            elapsed = time() - self.report_first_time
            self.logger.info('Pass so far %ds; %d objects expired' %
                             (elapsed, self.report_objects))
            self.report_last_time = time()

    def run_once(self, *args, **kwargs):
        """
        Executes a single pass, looking for objects to expire.

        :param args: Extra args to fulfill the Daemon interface; this daemon
                     has no additional args.
        :param kwargs: Extra keyword args to fulfill the Daemon interface; this
                       daemon accepts processes and process keyword args.
                       These will override the values from the config file if
                       provided.
        """
        self.logger.debug('Run begin')

        self.report_first_time = self.report_last_time = time()
        self.report_objects = 0

        rules = self.get_lifecycle_rules()
        for key, (_, conf) in rules.items():
            tenant, bucket, bucket_ts = key
            req = Request.blank('/v1/%s/%s?format=json' % (tenant, bucket),
                                environ={'REQUEST_METHOD': 'GET',
                                         'swift.authorize_override': True,
                                         'swift.authorize':
                                         lambda req: None})
            resp = req.get_response(self.swift)
            if resp.status_int == 404:
                self.logger.debug('Bucket not found, %s/%s.' %
                                  (tenant, bucket))
                continue
            if resp.status_int != 200:
                self.logger.error('Failed to list objects, %s/%s.' %
                                  (tenant, bucket))
                raise ExpirerError()
            if bucket_ts != \
               resp.headers['x-container-meta-[swift3]-timestamp']:
                continue
            for o in utils.json_to_objects(resp.body):
                req = Request.blank('/v1/%s/%s/%s' % (tenant, bucket,
                                                      o['name']),
                                    environ={'REQUEST_METHOD': 'HEAD',
                                             'swift.authorize_override': True,
                                             'swift.authorize':
                                             lambda req: None})
                resp = req.get_response(self.swift)
                if not resp.is_success:
                    self.logger.error('Failed to get object, %s/%s/%s.' %
                                      (tenant, bucket, o['name']))
                    raise ExpirerError()
                ctime = resp.headers['x-object-meta-[swift3]-timestamp']
                if ctime is None:
                    ctime = resp.headers['X-Timestamp']
                if conf.check_expiration(o['name'], ctime):
                    self.delete_object(tenant, bucket, o['name'])

        self.logger.debug('Run end')

        self.logger.debug('Remove out-dated rules')
        # keep only the latest rule
        for key, (paths, _) in rules.items():
            for p in paths[:-1]:
                req = Request.blank(p,
                                    environ={'REQUEST_METHOD': 'DELETE',
                                             'swift.authorize_override': True,
                                             'swift.authorize':
                                             lambda req: None})
                resp = req.get_response(self.swift)
                if not resp.is_success:
                    self.logger.info('Failed to remove a rule file, %s.' % p)
        self.logger.debug('Remove out-dated rules: done')

        self.report(final=True)
        # TODO: remove out-of-dated rules

    def _iso8601_to_datetime(self, iso_date):
        fmt = '%Y-%m-%dT%H:%M:%S'
        if '.' in iso_date:
            fmt += '.%f'
        if iso_date[-1] == 'Z':
            fmt += 'Z'

        return datetime.strptime(iso_date, fmt)

    def run_forever(self, *args, **kwargs):
        """
        Executes passes forever, looking for objects to expire.

        :param args: Extra args to fulfill the Daemon interface; this daemon
                     has no additional args.
        :param kwargs: Extra keyword args to fulfill the Daemon interface; this
                       daemon has no additional keyword args.
        """
        sleep(self.interval)
        while True:
            begin = time()
            try:
                self.run_once(*args, **kwargs)
            except ExpirerError:
                pass
            except (Exception, Timeout):
                self.logger.exception('Unhandled exception')
            elapsed = time() - begin
            if elapsed < self.interval:
                sleep((self.interval - elapsed))

    def delete_object(self, tenant, container, obj):
        try:
            req = Request.blank('/v1/%s/%s/%s' % (tenant, container, obj),
                                environ={'REQUEST_METHOD': 'DELETE',
                                         'swift.authorize_override': True,
                                         'swift.authorize': lambda req: None})
            resp = req.get_response(self.swift)
            if resp.status_int != 204:
                raise ExpirerError((tenant, container, obj))
            self.report_objects += 1
        except Exception as err:
            self.logger.exception(
                'Exception while deleting object %s %s %s' %
                (container, obj, str(err)))
            raise
        else:
            self.logger.debug('deleted object %s %s' % (container, obj))
        self.report()

    def get_lifecycle_rules(self):
        req = Request.blank('/v1/.swift3/lifecycle_rules?format=json',
                            environ={'REQUEST_METHOD': 'GET',
                                     'swift.authorize_override': True,
                                     'swift.authorize': lambda req: None})
        resp = req.get_response(self.swift)
        if resp.status_int != 200:
            self.logger.error('Failed to list rule files.')
            raise ExpirerError()

        objects = utils.json_to_objects(resp.body)

        targets = {}

        for o in objects:
            path = '/v1/.swift3/lifecycle_rules/' + o['name']
            req = Request.blank(path,
                                environ={'REQUEST_METHOD': 'GET',
                                         'swift.authorize_override': True,
                                         'swift.authorize': lambda req: None})
            resp = req.get_response(self.swift)
            if not resp.is_success:
                self.logger.error('Failed to get a rule file, %s.' % path)
                raise ExpirerError()

            tenant, bucket, bucket_ts, rule_ts = \
                split_path('/' + o['name'], 4, 4)

            if (tenant, bucket, bucket_ts) not in targets:
                targets[tenant, bucket, bucket_ts] = ([],
                                                      LifecycleConfHistory())

            targets[tenant, bucket, bucket_ts][0].append(path)
            targets[tenant, bucket, bucket_ts][1].append(
                LifecycleConf(resp.body, rule_ts))

        return targets
