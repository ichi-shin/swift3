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

from swift.common.swob import HTTPNotModified

from swift3.controllers.base import Controller
from swift3.response import InvalidArgument, PreconditionFailed, \
    MethodNotAllowed
from swift3 import utils
from swift3.etree import Element, SubElement, tostring
from swift3.acl import ACL, AllUsers


class ObjectController(Controller):
    """
    Handles requests on objects
    """
    def GETorHEAD(self, req):
        if 'versionId' in req.params:
            version_id = req.params['versionId']
            container, obj = req.find_version_object(self.app,
                                                     req.object_name,
                                                     version_id)
            req.container_name = container
            req.object_name = obj

        if req.method == 'HEAD':
            if 'range' in req.headers:
                # Swift doesn't handle Range header for HEAD requests.  We send
                # a GET request and drop the response body.
                resp = req.get_swift_object(self.app, access_check=True)
                resp.app_iter = None
            else:
                resp = req.head_swift_object(self.app, access_check=True)
        else:
            resp = req.get_swift_object(self.app, access_check=True)

        # The check of if_modified is not necessary with the upstream version
        # of Swift.
        if resp.last_modified and req.if_modified_since \
           and resp.last_modified <= req.if_modified_since:
            return HTTPNotModified()
        if resp.last_modified and req.if_unmodified_since \
           and resp.last_modified > req.if_unmodified_since:
            raise PreconditionFailed()

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
        return self.GETorHEAD(req)

    def GET(self, req):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(req)

    def PUT(self, req):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        if 'versionId' in req.params:
            raise InvalidArgument('versionId', req.params['versionId'],
                                  'This operation does not'
                                  'accept a version-id.')
        req.object_owner = req.user_id
        req.object_timestamp = utils.normalized_currrent_timestamp()

        acl = ACL(headers=req.headers)
        if not utils.ALLOW_CONTAINER_PUBLIC_WRITE:
            for p, g in acl:
                if p in ['WRITE', 'FULL_CONTROL'] \
                   and isinstance(g, AllUsers):
                    raise InvalidArgument('ACL', p,
                                          'Unsupported ACL for AllUsers')

        resp = req.put_swift_object(self.app, access_check=True)

        if req.copy_source is not None:
            req.headers['x-amz-copy-source'] = None
            req.put_s3_acl(self.app, self.logger, req.headers)
            result_elem = Element('CopyObjectResult', use_s3ns=False)
            SubElement(result_elem, 'LastModified').text = \
                resp.last_modified.isoformat()[:-6] + '.000Z'
            SubElement(result_elem, 'ETag').text = resp.etag
            resp.body = tostring(result_elem)
        else:
            req.put_s3_acl(self.app, self.logger,
                           xml=acl.to_xml(req.get_bucket_owner(self.app),
                                          req.user_id))

        expiration = req.get_expiration(self.app)
        if expiration:
            resp.headers['x-amz-expiration'] = expiration

        resp.status = 200
        resp.etag = resp.etag  # add '"'
        return resp

    def POST(self, req):
        raise MethodNotAllowed()

    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        if 'versionId' in req.params:
            version_id = req.params['versionId']
            container, obj = req.find_version_object(self.app,
                                                     req.object_name,
                                                     version_id)
            req.container_name = container
            req.object_name = obj
            versioning_check = False
        else:
            versioning_check = True

        resp = req.delete_swift_object(self.app, access_check=True,
                                       versioning_check=versioning_check)

        resp.status = 204
        return resp
