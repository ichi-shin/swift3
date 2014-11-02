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

from swift3.controllers.base import Controller
from swift3.response import HTTPOk, AccessDenied, MissingSecurityHeader, \
    UnexpectedContent
from swift3.subresource import ACL
from swift3.utils import LOGGER


def get_acl(headers, body, bucket_owner, object_owner=None):
    """
    Get ACL from headers or body.
    """
    acl = ACL.from_headers(headers, bucket_owner, object_owner)

    if acl is None:
        # Get acl from request body if possible.
        if not body:
            msg = 'Your request was missing a required header'
            raise MissingSecurityHeader(msg, missing_header_name='x-amz-acl')

        acl = ACL(body)
    else:
        if body:
            # Specifying grant with both header and xml is not allowed.
            raise UnexpectedContent

    return acl


class AclController(Controller):
    """
    Handles the following APIs:

     - GET Bucket acl
     - PUT Bucket acl
     - GET Object acl
     - PUT Object acl

    Those APIs are logged as ACL operations in the S3 server log.
    """
    def GET(self, req):
        """
        Handles GET Bucket acl and GET Object acl.
        """
        if req.is_object_request:
            info = req.get_object_info(self.app)
        else:
            info = req.get_bucket_info(self.app)

        acl = info['acl']
        acl.check_permission(req.user_id, 'READ_ACP')

        resp = HTTPOk()
        resp.body = acl.xml

        return resp

    def PUT(self, req):
        """
        Handles PUT Bucket acl and PUT Object acl.
        """
        if req.is_object_request:
            bucket_info = req.get_bucket_info(self.app)
            object_info = req.get_object_info(self.app)

            acl = get_acl(req.headers, req.xml(ACL.max_xml_length),
                          bucket_info['acl'].owner, object_info['acl'].owner)

            if acl.owner != object_info['acl'].owner:
                # It is not allowed to change an owner.
                raise AccessDenied()

            object_info['acl'].check_permission(req.user_id, 'WRITE_ACP')

            for permission, grantee in acl.grant:
                LOGGER.info('Grant %s %s permission on the object /%s/%s' %
                            (grantee, permission, req.container_name,
                             req.object_name))

            req.object_acl = acl

            # Send the original metadata since a POST Object request will
            # remove all the existing metadata.
            headers = {}
            for key, val in object_info['meta'].iteritems():
                headers['x-object-meta-' + key] = val

            req.get_response(self.app, 'POST', headers=headers)
        else:
            bucket_info = req.get_bucket_info(self.app)

            acl = get_acl(req.headers, req.xml(ACL.max_xml_length),
                          bucket_info['acl'].owner)

            if acl.owner != bucket_info['acl'].owner:
                # It is not allowed to change an owner.
                raise AccessDenied()

            bucket_info['acl'].check_permission(req.user_id, 'WRITE_ACP')

            for permission, grantee in acl.grant:
                LOGGER.info('Grant %s %s permission on the bucket /%s' %
                            (grantee, permission, req.container_name))

            req.bucket_acl = acl
            req.get_response(self.app, 'POST')

        return HTTPOk()
