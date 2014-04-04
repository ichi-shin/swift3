# Copyright (c) 2010-2014 OpenStack Foundation.
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

from swift3.exception import NotS3Request
from swift3.request import Request
from swift3.response import ErrorResponse, InternalError, MethodNotAllowed, \
    ResponseBase, Response
from swift3.cfg import CONF
from swift3.utils import LOGGER


class Swift3Middleware(object):
    """Swift3 S3 compatibility midleware"""
    def __init__(self, app, *args, **kwargs):
        self.app = app

    def __call__(self, env, start_response):
        req = None
        bucket_info = None
        try:
            s3_env = env.copy()
            if 'RAW_PATH_INFO' not in s3_env:
                # emulate raw path info for older eventlet
                s3_env['RAW_PATH_INFO'] = quote(s3_env['PATH_INFO'])
            req = Request(s3_env)
            req.authenticate(self.app)

            resp = self.handle_request(req)
        except NotS3Request:
            resp = self.app
        except ErrorResponse as err_resp:
            if isinstance(err_resp, InternalError):
                LOGGER.exception(err_resp)
            resp = err_resp
        except Exception, e:
            LOGGER.exception(e)
            resp = InternalError(reason=e)

        if isinstance(resp, ResponseBase) and 'swift.trans_id' in env:
            resp.headers['x-amz-id-2'] = env['swift.trans_id']
            resp.headers['x-amz-request-id'] = env['swift.trans_id']

        if req and req.container_name:
            try:
                if req.method == 'DELETE' and req.container_name and \
                        not req.object_name:
                    # check deleted cache for DELETE Bucket requests
                    req._cache = req._deleted_cache

                bucket_info = req.get_bucket_info(self.app)
            except Exception:
                pass

        if req and req.user_id and bucket_info:
            # TODO: should we set loginfo in Request class?
            log_info = env.setdefault('swift.log_info', [])
            log_info.append('bucket_owner:' + bucket_info['acl'].owner)
            log_info.append('requester:' + req.user_id)
            log_info.append('bucket:' + req.container_name)
            log_info.append('tenant:' + req.tenant_name)
            if req.object_name:
                log_info.append('key:' + req.object_name)

                if req.method == 'PUT' and req.object_size is not None:
                    log_info.append('object_size:' + str(req.object_size))

                if isinstance(resp, Response):
                    info = resp.object_info  # pylint: disable-msg=E1103
                    if info['version_id']:
                        log_info.append('version_id:' + info['version_id'])
            log_info.append('resource_type:' + req.controller.resource_type())

            if isinstance(resp, ErrorResponse):
                log_info.append('error_code:' + resp._code)

        env['swift.leave_relative_location'] = True

        return resp(env, start_response)

    def handle_request(self, req):
        LOGGER.debug('Calling Swift3 Middleware')
        LOGGER.debug(req.__dict__)

        controller = req.controller(self.app)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(req)
        else:
            raise MethodNotAllowed(req.method,
                                   req.controller.resource_type())

        return res


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    CONF.update(global_conf)
    CONF.update(local_conf)

    return Swift3Middleware
