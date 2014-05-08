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


class AclController(Controller):
    """
    Handles ACL requests
    """
    def GET(self, req):
        version_id = \
            req.params['versionId'] if 'versionId' in req.params else ''

        xml = req.get_s3_acl_xml(self.app, version_id, access_check=True)

        if not version_id and req.object_name:
            version_id = req.get_object_version_id(self.app)

        headers = {}
        if version_id:
            headers = {'x-amz-version-id': version_id}

        return HTTPOk(body=xml, headers=headers)

    def PUT(self, req):
        version_id = \
            req.params['versionId'] if 'versionId' in req.params else ''

        resp = req.put_s3_acl(self.app, self.logger, headers=req.headers,
                              xml=req.body, version_id=version_id,
                              access_check=True)

        if not version_id and req.object_name:
            version_id = req.get_object_version_id(self.app)

        if version_id:
            resp.headers['x-amz-version-id'] = version_id
        resp.status = 200
        resp.headers['Location'] = req.container_name
        return resp
