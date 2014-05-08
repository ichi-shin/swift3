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

from swift.common.swob import HTTPOk

from swift3.controllers.base import Controller
from swift3 import utils


class LocationController(Controller):
    """
    Handles location requests
    """
    def GET(self, req):
        req.check_bucket_owner(self.app)
        req.head_swift_container(self.app, access_check=True)

        body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<LocationConstraint '
                'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"')

        if utils.LOCATION == 'US':
            body += '/>'
        else:
            body += ('>%s</LocationConstraint>' % utils.LOCATION)
        return HTTPOk(body=body, content_type='application/xml')
