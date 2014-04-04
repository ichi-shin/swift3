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

from swift3.controllers.base import Controller
from swift3.controllers.obj import ObjectController
from swift3.response import HTTPOk, AccessDenied, MissingSecurityHeader, \
    UnexpectedContent
from swift3.subresource import ACL
from swift3.utils import LOGGER


def get_acl(bucket_owner, object_owner, req):
    acl = ACL.from_headers(req.headers, bucket_owner, object_owner)
    body = req.xml(ACL.max_xml_length)

    if acl is None:
        # get acl from request body if possible
        if not body:
            msg = 'Your request was missing a required header'
            raise MissingSecurityHeader(msg, missing_header_name='x-amz-acl')

        acl = ACL(body)
    else:
        if body:
            # Specifying grant with both header and xml is not allowed
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
        version_id = req.params.get('versionId')

        if req.object_name:
            controller = ObjectController(self.app)
            resp = controller._head_object(req, version_id=version_id)
            info = resp.object_info
        else:
            info = req.get_bucket_info(self.app)

        acl = info['acl']
        acl.check_permission(req.user_id, 'READ_ACP')

        resp = HTTPOk()
        resp.body = acl.xml
        if 'version_id' in info:
            resp.headers['x-amz-version-id'] = info['version_id']

        return resp

    def PUT(self, req):
        """
        Handles PUT Bucket acl and PUT Object acl.
        """
        version_id = req.params.get('versionId')

        if req.object_name:
            bucket_info = req.get_bucket_info(self.app)

            controller = ObjectController(self.app)
            resp = controller._head_object(req, version_id=version_id)
            object_info = resp.object_info

            acl = get_acl(bucket_info['acl'].owner, object_info['acl'].owner,
                          req)

            if acl.owner != object_info['acl'].owner:
                # We cannot change owner.
                raise AccessDenied()

            object_info['acl'].check_permission(req.user_id, 'WRITE_ACP')

            for permission, grantee in acl.grant:
                LOGGER.info('Grant %s %s permission on the object /%s/%s' %
                            (grantee, permission, req.container_name,
                             req.object_name))

            req.object_acl = acl

            # Copy the original metadata since Swift POST Object API removes
            # all the existing metadata.
            req.version_id = object_info['version_id']
            req.delete_marker = object_info['delete_marker']
            headers = {}
            for key, val in object_info['meta'].iteritems():
                headers['x-object-meta-' + key] = val

            # set an unmodified header to make sure that no one updates the
            # target object after we got object_info
            headers['if-unmodified-since'] = object_info['last_modified']

            container, obj = None, None
            if version_id:
                container, obj = self.find_version_object(req, version_id)
            req.get_response(self.app, 'POST', container, obj, headers)
        else:
            bucket_info = req.get_bucket_info(self.app)
            object_info = None

            acl = get_acl(bucket_info['acl'].owner, None, req)

            if acl.owner != bucket_info['acl'].owner:
                # We cannot change owner.
                raise AccessDenied()

            bucket_info['acl'].check_permission(req.user_id, 'WRITE_ACP')

            for permission, grantee in acl.grant:
                LOGGER.info('Grant %s %s permission on the bucket /%s' %
                            (grantee, permission, req.container_name))

            req.bucket_acl = acl
            req.get_response(self.app, 'POST')

        resp = HTTPOk()
        if object_info and 'version_id' in object_info:
            resp.headers['x-amz-version-id'] = object_info['version_id']

        return resp
