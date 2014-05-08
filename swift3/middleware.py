# Copyright (c) 2010-2014 OpenStack Foundation.
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

"""
The swift3 middleware will emulate the S3 REST api on top of swift.

The following operations are currently supported:

    * GET Service
    * DELETE Bucket
    * GET Bucket (List Objects)
    * PUT Bucket
    * DELETE Object
    * Delete Multiple Objects
    * GET Object
    * HEAD Object
    * PUT Object
    * PUT Object (Copy)

To add this middleware to your configuration, add the swift3 middleware
in front of the auth middleware, and before any other middleware that
look at swift requests (like rate limiting).

To set up your client, the access key will be the concatenation of the
account and user strings that should look like test:tester, and the
secret access key is the account password.  The host should also point
to the swift storage hostname.  It also will have to use the old style
calling format, and not the hostname based container format.

An example client using the python boto library might look like the
following for an SAIO setup::

    from boto.s3.connection import S3Connection
    connection = S3Connection(
        aws_access_key_id='test:tester',
        aws_secret_access_key='testing',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())
"""

from urllib import quote

from swift.common.utils import get_logger
from swift.common.swob import Response

from swift3.response import S3ErrorResponse, InternalError, MethodNotAllowed, \
    S3Response
from swift3.request import S3Request
from swift3.exception import NotS3Request
from swift3 import utils


class Swift3Middleware(object):
    """Swift3 S3 compatibility midleware"""
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='swift3')

        utils.update_swift3_conf(conf)

    def __call__(self, env, start_response):
        req = None
        tenant = None
        bucket_owner = 'undefined'
        bucket_ts = None
        try:
            s3_env = env.copy()
            if 'RAW_PATH_INFO' not in s3_env:
                # emulate raw path info for older eventlet
                s3_env['RAW_PATH_INFO'] = quote(s3_env['PATH_INFO'])
            req = S3Request(s3_env)
            tenant, user_id, bucket_owner, bucket_ts = \
                req.get_basic_info(self.app)
            resp = self.handle_request(req)
            try:
                if bucket_owner == 'undefined' and req.container_name:
                    bucket_owner = req.get_bucket_owner(self.app)
                    if not bucket_ts and req.container_name:
                        bucket_ts = req.get_container_ts(self.app)
            except Exception:
                pass
        except NotS3Request:
            resp = self.app
        except S3ErrorResponse as err_resp:
            if isinstance(err_resp, InternalError):
                self.logger.exception(err_resp)
            resp = err_resp
        except Exception as e:
            self.logger.exception(e)
            resp = InternalError(reason=e)

        if isinstance(resp, Response) and 'swift.trans_id' in env:
            resp.headers['x-amz-id-2'] = env['swift.trans_id']
            resp.headers['x-amz-request-id'] = env['swift.trans_id']

        # TODO: should we set loginfo in Request class?
        log_info = env.setdefault('swift.log_info', [])
        if req and tenant and bucket_owner != 'undefined' and bucket_ts:
            log_info.append('bucket_owner:' + bucket_owner)
            log_info.append('requester:' + user_id)
            log_info.append('bucket:' + req.container_name)
            log_info.append('bucket_ts:' + str(bucket_ts))
            log_info.append('tenant:' + tenant)
            if req.object_name:
                log_info.append('key:' + req.object_name)
            if req.object_size is not None:
                log_info.append('object_size:' + str(req.object_size))
            if isinstance(resp, S3Response) and resp.versioned:
                # FIXME: cleanup
                from swift3.request import VersionId
                version_id = str(VersionId(resp.object_timestamp))
                log_info.append('version_id:' + version_id)
            log_info.append('resource_type:' +
                            req.get_controller().get_resource_type())

        if isinstance(resp, S3ErrorResponse):
            log_info.append('error_code:' + resp.__class__.__name__)

        env['swift.leave_relative_location'] = True

        return resp(env, start_response)

    def handle_request(self, req):
        self.logger.debug('Calling Swift3 Middleware')
        self.logger.debug(req.__dict__)

        controller = req.get_controller()(self.app, self.logger)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(req)
        else:
            raise MethodNotAllowed()

        return res


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def swift3_filter(app):
        return Swift3Middleware(app, conf)

    return swift3_filter
