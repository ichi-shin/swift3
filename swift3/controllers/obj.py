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

from swift.common.http import HTTP_OK

from swift3.controllers.base import Controller
from swift3.response import AccessDenied, HTTPOk, HeaderKeyDict, \
    MethodNotAllowed, NoSuchKey, InvalidArgument
from swift3.subresource import ACLPrivate
from swift3.etree import Element, SubElement, tostring


class ObjectController(Controller):
    """
    Handles requests on objects
    """
    def GETorHEAD(self, req, version_id):
        """
        """
        # Check the target bucket first.  AWS S3 returns NoSuchBucket if the
        # target bucket doesn't exist.
        bucket_info = req.get_bucket_info(self.app)

        container, obj = None, None
        if version_id:
            container, obj = self.find_version_object(req, version_id)

        resp = req.get_response(self.app, container=container, obj=obj)

        resp.object_info['acl'].check_permission(req.user_id, 'READ')

        if req.method == 'HEAD':
            resp.app_iter = None

        if resp.object_info['delete_marker']:
            # TODO: set proper headers
            headers = HeaderKeyDict(resp.headers)
            if version_id:
                if headers.get('Content-Length'):
                    del(headers['Content-Length'])

                if req.method == 'HEAD':
                    req.object_size = 0
                raise MethodNotAllowed(req.method, 'DeleteMarker',
                                       headers=headers)
            else:
                if not resp.headers['x-amz-version-id']:
                    resp.headers['x-amz-version-id'] = 'null'
                raise NoSuchKey(key=req.object_name, headers=headers)

        if bucket_info['versioning']:
            if not resp.headers['x-amz-version-id']:
                resp.headers['x-amz-version-id'] = 'null'

        for key in ('content-type', 'content-language', 'expires',
                    'cache-control', 'content-disposition',
                    'content-encoding'):
            if 'response-' + key in req.params:
                resp.headers[key] = req.params['response-' + key]

        return resp

    def HEAD(self, req):
        """
        Handle HEAD Object request
        """
        return self.GETorHEAD(req, req.params.get('versionId'))

    def GET(self, req):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(req, req.params.get('versionId'))

    def PUT(self, req):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        if 'versionId' in req.params:
            raise InvalidArgument('versionId', req.params['versionId'],
                                  'This operation does not accept a '
                                  'version-id.')

        bucket_info = req.get_bucket_info(self.app)
        bucket_info['acl'].check_permission(req.user_id, 'WRITE')

        resp = req.get_response(self.app)

        if bucket_info['versioning'] is None:
            if 'x-amz-version-id' in resp.headers:
                del resp.headers['x-amz-version-id']
        else:
            resp.headers['x-amz-version-id'] = req.version_id

        if 'HTTP_X_COPY_FROM' in req.environ:
            elem = Element('CopyObjectResult')
            SubElement(elem, 'ETag').text = '"%s"' % resp.etag
            body = tostring(elem, use_s3ns=False)
            return HTTPOk(body=body)

        resp.status = HTTP_OK

        return resp

    def POST(self, req):
        raise AccessDenied()

    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        bucket_info = req.get_bucket_info(self.app)
        bucket_info['acl'].check_permission(req.user_id, 'WRITE')
        version_id = req.params.get('versionId')

        if version_id is None and bucket_info['versioning'] is not None:
            # create delete marker
            req.object_acl = ACLPrivate(req.user_id)
            req.delete_marker = 'true'
            self.add_version_id(req)
            resp = req.get_response(self.app, 'PUT', body='')
            resp.headers['x-amz-version-id'] = req.version_id
        else:
            container, obj = None, None
            if version_id:
                container, obj = self.find_version_object(req, version_id)

            resp = req.get_response(self.app, 'DELETE', container, obj)

        resp.status = 204
        return resp
