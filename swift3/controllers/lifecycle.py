# Copyright (c) 2014 OpenStack Foundation.
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
from swift3.response import HTTPOk, HTTPNoContent, InvalidBucketState, \
    NoSuchLifecycleConfiguration
from swift3.subresource import Lifecycle


class LifecycleController(Controller):
    """
    Handles lifecycle requests
    """
    @bucket_operation
    @bucket_owner_required
    def GET(self, req):
        bucket_info = req.get_bucket_info(self.app)

        lifecycle = bucket_info['lifecycle']
        if lifecycle is None:
            # lifecycle is not enabled
            raise NoSuchLifecycleConfiguration()

        return HTTPOk(body=lifecycle.xml)

    @bucket_operation
    @bucket_owner_required
    def PUT(self, req):
        conf = req.subresource(Lifecycle, check_md5=True)

        bucket_info = req.get_bucket_info(self.app)

        if bucket_info['versioning'] is not None:
            err_msg = 'Lifecycle configuration is currently not supported ' \
                'on a versioned bucket.'
            raise InvalidBucketState(err_msg)

        req.lifecycle = conf
        req.get_response(self.app, 'POST')

        return HTTPOk()

    @bucket_operation
    @bucket_owner_required
    def DELETE(self, req):
        del req.lifecycle

        req.get_response(self.app, 'POST')

        return HTTPNoContent()
