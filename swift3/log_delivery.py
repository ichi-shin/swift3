# Copyright (c) 2010-2014 OpenStack Foundation
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

import os
import hashlib
import time
import gzip
from datetime import datetime
from urllib import unquote
from time import sleep

from swift.common.daemon import Daemon
from swift.common.swob import Request
from swift.common import utils, wsgi

from swift3.acl import LoggingStatus
from swift3.utils import normalized_currrent_timestamp, json_to_objects
from swift3.exception import LogUploadError
from swift3 import acl


class NotS3Log(Exception):
    pass


class LogDelivery(Daemon):
    '''
    Given a local directory, a swift account, and a container name, LogParser
    will upload all files in the local directory to the given account/
    container.  All but the newest files will be uploaded, and the files' md5
    sum will be computed. The hash is used to prevent duplicate data from
    being uploaded multiple times in different files (ex: log lines). Since
    the hash is computed, it is also used as the uploaded object's etag to
    ensure data integrity.

    Note that after the file is successfully uploaded, it will be unlinked.

    The given proxy server config is used to instantiate a proxy server for
    the object uploads.

    The default log file format is: plugin_name-%Y%m%d%H* . Any other format
    of log file names must supply a regular expression that defines groups
    for year, month, day, and hour. The regular expression will be evaluated
    with re.VERBOSE. A common example may be:
    source_filename_pattern = ^cdn_logger-
        (?P<year>[0-9]{4})
        (?P<month>[0-1][0-9])
        (?P<day>[0-3][0-9])
        (?P<hour>[0-2][0-9])
        .*$
    '''

    def __init__(self, conf, cutoff=None):
        super(LogDelivery, self).__init__(conf)
        self.logger = utils.get_logger(conf, log_route='log-delivery')
        self.log_dir = conf.get('log_dir', '/var/log/swift/')
        conf_path = conf.get('__file__') or '/etc/swift/proxy-server.conf'
        self.swift = wsgi.loadapp(conf_path, conf)
        self.swift_user = conf.get('log_user', '.log_delivery')
        self.interval = int(conf.get('interval', '3600'))
        self.new_log_cutoff = int(cutoff or conf.get('new_log_cutoff', '7200'))
        self.owners = {}

    def run_once(self, *args, **kwargs):
        self.logger.info("Uploading logs")
        start = time.time()
        self.upload_all_logs()
        self.logger.info("Uploading logs complete (%0.2f minutes)" %
                         ((time.time() - start) / 60))

    def run_forever(self, *args, **kwargs):
        while True:
            self.run_once(*args, **kwargs)
            sleep(self.interval)

    def get_files_under_log_dir(self):
        """
        Look under log_dir recursively and return all filenames

        :returns : list of strs, the abspath to all filenames under log_dir
        """
        for path, dirs, files in os.walk(self.log_dir):
            for f in files:
                yield os.path.join(path, f)

    def upload_all_logs(self):
        """
        Match files under log_dir to source_filename_pattern and upload to
        swift
        """
        for filename in self.get_files_under_log_dir():
            self.logger.info(filename)
            # don't process very new logs
            try:
                mtime = os.stat(filename).st_mtime
                seconds_since_mtime = time.time() - mtime
            except OSError:
                # filename wasn't found, skip it
                continue
            if seconds_since_mtime < self.new_log_cutoff:
                self.logger.debug("Skipping log: %(file)s "
                                  "(< %(cutoff)d seconds old)" %
                                  {'file': filename,
                                   'cutoff': self.new_log_cutoff})
                continue
            try:
                self.upload_one_log(filename, mtime)
            except Exception:
                self.logger.exception(
                    'ERROR: could not upload %s' % filename)

    def translate_line(self, line):
        try:
            client_ip, remote_addr, date_time, method, path, protocol, \
                status, referer, user_agent, auth_token, recvd, sent, etag, \
                tx_id, headers, request_time, source, log_info, start_time, \
                end_time = (unquote(x) for x in line.split(' ')[-20:])
            log_info = dict([data.split(':', 1) for data
                             in log_info.split(',')])
            requester = log_info.get('requester', '-')
            resource_type = log_info.get('resource_type', '-')  # FIXME
            object_size = log_info.get('object_size', '-')  # FIXME
            version_id = log_info.get('version_id', '-')  # FIXME
            bucket_owner = log_info.get('bucket_owner', '-')
            tenant = log_info.get('tenant', None)
            bucket_ts = log_info.get('bucket_ts', None)
            error_code = log_info.get('error_code', '-')
            bucket = log_info.get('bucket', None)  # TODO: use domain_remap and
            key = log_info.get('key', '-')        # get bucket from path
            operation = "REST.%s.%s" % (method.upper(), resource_type)
            uri = '"%s %s"' % (method, path)

            if tenant is None or bucket is None or bucket_ts is None:
                # we cannot know whether logging is enabled on the bucket
                raise NotS3Log()
        except ValueError:
            raise NotS3Log()

        self.owners[tenant, bucket, bucket_ts] = bucket_owner

        return (tenant, bucket, bucket_ts), \
            (bucket_owner, bucket, date_time, client_ip, requester,
             tx_id, operation, key, uri, status, error_code, sent,
             object_size, str(int(float(request_time) * 1000)),
             '-', referer, user_agent, version_id)

    def generate_s3_log(self, filename):
        """
        Generate S3 log date from proxy server log
        """
        if os.path.getsize(filename) == 0:
            self.logger.debug("Log %s is 0 length, skipping" % filename)
            return
        self.logger.debug("Processing log: %s" % filename)
        log_data = {}
        opener = gzip.open if filename.endswith('.gz') else open
        f = opener(filename, 'rb')
        try:
            for line in f:
                try:
                    key, log = self.translate_line(line)
                except NotS3Log:
                    continue

                if key not in log_data:
                    log_data.update({key: ([], hashlib.md5())})
                lines, hash = log_data[key]
                l = ' '.join(log) + '\n'
                lines.append(l)
                hash.update(l)
        finally:
            f.close()

        for bucket in log_data:
            lines, hash = log_data[bucket]
            log_data[bucket] = ''.join(lines), hash.hexdigest()

        return log_data

    def upload_one_log(self, filename, ts):
        """
        Upload one file to swift
        """
        # By adding a hash to the filename, we ensure that uploaded files
        # have unique filenames and protect against uploading one file
        # more than one time. By using md5, we get an etag for free.
        log_data = self.generate_s3_log(filename)
        d = datetime.utcfromtimestamp(ts)
        time_str = d.strftime("%Y-%m-%d-%H-%M-%S")

        logging_buckets = self.get_logging_buckets()
        for key, conf in logging_buckets.items():
            if key in log_data:
                tenant, bucket, ts = key

                c_resp = self.head_container(tenant, conf.target_bucket)
                if c_resp.status_int == 404:
                    self.logger.info("%s/%s/%s does not exist" %
                                     (tenant, conf.target_bucket))
                    continue
                elif not c_resp.is_success:
                    self.logger.error("Failed to head  %s/%s/%s" %
                                      (tenant, conf.target_bucket))
                    raise LogUploadError()

                bucket_owner = self.owners[tenant, bucket, ts]
                bucket_timestamp = \
                    c_resp.headers['x-container-meta-[swift3]-timestamp']

                acl_obj = '%s/%s/%s' % (tenant, conf.target_bucket,
                                        bucket_timestamp)

                resp = self.get_object('.swift3', 'acl', acl_obj)
                if resp.status_int == 404:
                    # the bucket has private permission
                    self.logger.debug("Not found ACL info, %s." % acl_obj)
                    self.logger.info("log_delivery doesn't have permission"
                                     " to upload log file")
                    continue
                elif not resp.is_success:
                    self.logger.error("Failed to get bucket ACL from %s" %
                                      acl_obj)
                    raise LogUploadError()

                acl_info = acl.ACL(xml=resp.body)
                if self.swift_user not in acl_info['WRITE'] or \
                        self.swift_user not in acl_info['READ_ACP']:
                    self.logger.info("log_delivery doesn't have permission"
                                     " to upload log file")
                    continue

                lines, hash = log_data[key]
                obj = '%s%s-%s' % (conf.target_prefix, time_str, hash)
                object_owner = self.swift_user
                object_timestamp = normalized_currrent_timestamp()
                resp = self.upload_object(tenant, conf.target_bucket, obj,
                                          {'x-object-meta-[swift3]-owner':
                                           object_owner,
                                           'x-object-meta-[swift3]-timestamp':
                                           object_timestamp},
                                          lines)
                if not resp.is_success:
                    self.logger.error("Failed to upload log %s to %s/%s/%s" %
                                      (filename, tenant, conf.target_bucket,
                                       obj))
                    raise LogUploadError()

                self.logger.debug("Uploaded log %s to %s/%s/%s" %
                                  (filename, tenant, conf.target_bucket, obj))

                grant = [
                    ('FULL_CONTROL', acl.LogDelivery()),
                    ('FULL_CONTROL', acl.User(self.owners[tenant, bucket,
                                                          ts])),
                ]
                grant.extend(conf.target_grants)

                acl_obj = '%s/%s/%s/%s/%s' % (tenant, conf.target_bucket,
                                              bucket_timestamp, obj,
                                              object_timestamp)
                xml = acl.ACL(grant).to_xml(bucket_owner, object_owner)
                resp = self.upload_object('.swift3', 'acl', acl_obj, {}, xml)
                if not resp.is_success:
                    self.logger.error("Failed to put acl to %s" % acl_obj)
                else:
                    self.logger.debug("Put acl to %s" % acl_obj)

        os.unlink(filename)

    def get_logging_buckets(self):
        req = Request.blank('/v1/.swift3/logging_conf?format=json',
                            environ={'REQUEST_METHOD': 'GET',
                                     'swift.authorize_override': True,
                                     'swift.authorize': lambda req: None})
        resp = req.get_response(self.swift)
        if not resp.is_success:
            self.logger.error("Failed to list logging conf.")
            raise LogUploadError()

        objects = json_to_objects(resp.body)
        targets = {}

        for o in objects:
            req = Request.blank('/v1/.swift3/logging_conf/' + o['name'],
                                environ={'REQUEST_METHOD': 'GET',
                                         'swift.authorize_override': True,
                                         'swift.authorize': lambda req: None})
            resp = req.get_response(self.swift)
            if not resp.is_success:
                self.logger.error("Failed to get logging conf, %s.", o['name'])
                raise LogUploadError()

            tenant, bucket, ts = utils.split_path('/' + o['name'], 3, 3)
            status = LoggingStatus(resp.body)
            if status.target_bucket:
                # Logging is enabled
                targets[tenant, bucket, ts] = status

        return targets

    def upload_object(self, tenant, container, obj, headers, body):
        req = Request.blank('/v1/%s/%s/%s' % (tenant, container, obj),
                            environ={'REQUEST_METHOD': 'PUT',
                                     'swift.authorize_override': True,
                                     'swift.authorize': lambda req: None},
                            headers=headers, body=body)
        return req.get_response(self.swift)

    def head_container(self, tenant, container):
        req = Request.blank('/v1/%s/%s' % (tenant, container),
                            environ={'REQUEST_METHOD': 'HEAD',
                                     'swift.authorize_override': True,
                                     'swift.authorize': lambda req: None})
        return req.get_response(self.swift)

    def head_object(self, tenant, container, obj):
        req = Request.blank('/v1/%s/%s/%s' % (tenant, container, obj),
                            environ={'REQUEST_METHOD': 'HEAD',
                                     'swift.authorize_override': True,
                                     'swift.authorize': lambda req: None})
        return req.get_response(self.swift)

    def get_object(self, tenant, container, obj):
        req = Request.blank('/v1/%s/%s/%s' % (tenant, container, obj),
                            environ={'REQUEST_METHOD': 'GET',
                                     'swift.authorize_override': True,
                                     'swift.authorize': lambda req: None})
        return req.get_response(self.swift)
