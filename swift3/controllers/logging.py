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

from swift3.controllers.base import Controller, bucket_owner_required, \
    bucket_operation
from swift3.subresource import LoggingStatus
from swift3.etree import Element, tostring
from swift3.response import HTTPOk, NoSuchBucket, AccessDenied, \
    InvalidTargetBucketForLogging, NoLoggingStatusForKey
from swift3.cfg import CONF


class LoggingStatusController(Controller):
    """
    Handles the following APIs:

     - GET Bucket logging
     - PUT Bucket logging

    Those APIs are logged as LOGGING_STATUS operations in the S3 server log.
    """
    @bucket_operation(err_resp=NoLoggingStatusForKey)
    @bucket_owner_required
    def GET(self, req):
        """
        Handles GET Bucket logging.
        """
        bucket_info = req.get_bucket_info(self.app)

        logging = bucket_info['logging']
        if logging is None:
            xml = tostring(Element('BucketLoggingStatus'))
        else:
            xml = logging.xml

        return HTTPOk(body=xml)

    @bucket_operation(err_resp=NoLoggingStatusForKey)
    @bucket_owner_required
    def PUT(self, req):
        """
        Handles PUT Bucket logging.
        """
        conf = req.subresource(LoggingStatus)

        if conf.target_bucket:
            try:
                info = req.get_bucket_info(self.app, conf.target_bucket)
            except NoSuchBucket:
                msg = 'The target bucket for logging does not exist'
                raise InvalidTargetBucketForLogging(conf.target_bucket, msg)
            acl = info['acl']

            if acl.owner != req.user_id:
                msg = 'The owner for the bucket to be logged and the ' \
                    'target bucket must be the same.'
                raise InvalidTargetBucketForLogging(conf.target_bucket, msg)

            try:
                acl.check_permission(CONF.log_delivery_user, 'READ_ACP')
                acl.check_permission(CONF.log_delivery_user, 'WRITE')
            except AccessDenied:
                msg = 'You must give the log-delivery group WRITE and ' \
                    'READ_ACP permissions to the target bucke'
                raise InvalidTargetBucketForLogging(conf.target_bucket, msg)

        req.logging = conf
        req.get_response(self.app, 'POST')

        return HTTPOk()
