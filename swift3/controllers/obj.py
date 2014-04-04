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

from swift.common.swob import HeaderKeyDict

from swift3.controllers.base import Controller
from swift3.response import InvalidArgument, MethodNotAllowed, \
    PreconditionFailed, InvalidRequest, NoSuchBucket, NoSuchKey
from swift3.subresource import ACL, ACLPrivate
from swift3.etree import Element, SubElement, tostring
from swift3.utils import valid_container_name, normalized_currrent_timestamp


class ObjectController(Controller):
    """
    Handles requests on objects
    """
    def get_expiration(self, req, obj, creation_ts):
        bucket_info = req.get_bucket_info(self.app)
        lifecycle = bucket_info['lifecycle']
        if lifecycle is None:
            return None

        return lifecycle.to_header(obj, creation_ts)

    def get_or_head_object(self, method, req, version_id):
        """
        """
        # Check the target bucket first.  AWS S3 returns NoSuchBucket if the
        # target bucket doesn't exist.
        bucket_info = req.get_bucket_info(self.app)

        container, obj = None, None
        if version_id:
            container, obj = self.find_version_object(req, version_id)

        if method == 'HEAD' and 'range' in req.headers:
            # Swift doesn't handle Range header for HEAD requests.  We
            # send a GET request and drop the response body.
            resp = req.get_response(self.app, 'GET', container, obj)
            resp.app_iter = None
        else:
            resp = req.get_response(self.app, method, container, obj)

        # FIXME: cleanup
        req.object_size = resp.content_length

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

        expiration_header = self.get_expiration(req, req.object_name,
                                                resp.object_info['ts'])
        if expiration_header is not None:
            resp.headers['x-amz-expiration'] = expiration_header

        if bucket_info['versioning']:
            if not resp.headers['x-amz-version-id']:
                resp.headers['x-amz-version-id'] = 'null'

        for key in ('content-type', 'content-language', 'expires',
                    'cache-control', 'content-disposition',
                    'content-encoding'):
            if 'response-' + key in req.params:
                resp.headers[key] = req.params['response-' + key]

        return resp

    def _head_object(self, req, version_id=None):
        """
        """
        return self.get_or_head_object('HEAD', req, version_id)

    def HEAD(self, req):
        """
        Handle HEAD Object request
        """
        resp = self._head_object(req, req.params.get('versionId'))

        resp.object_info['acl'].check_permission(req.user_id, 'READ')

        return resp

    def _get_object(self, req, version_id=None):
        """
        """
        return self.get_or_head_object('GET', req, version_id)

    def GET(self, req):
        """
        Handle GET Object request
        """
        resp = self._get_object(req, req.params.get('versionId'))

        resp.object_info['acl'].check_permission(req.user_id, 'READ')

        return resp

    def check_copy_source(self, req):
        if req.content_length > 0:
            err_msg = 'The request included a body. Requests of this' \
                ' type must not include a non-empty body.'
            raise InvalidRequest(err_msg)

        bucket, obj, version_id = req.copy_source

        if not valid_container_name(bucket):
            raise NoSuchBucket(bucket)

        if req.metadata_directive != 'REPLACE' and \
                bucket == req.container_name and obj == req.object_name:
            err_msg = "This copy request is illegal because it is trying" \
                " to copy an object to itself without changing the" \
                " object's metadata."
            raise InvalidRequest(err_msg)

    def _put_object(self, req):
        headers = None

        if req.copy_source is not None:
            self.check_copy_source(req)

            headers = HeaderKeyDict()
            headers.update(req.copy_source_headers)

            bucket, obj, version_id = req.copy_source

            with req.target(bucket, obj):
                # Make sure that the source bucket exists and the source object
                # is not a deleter marker.
                src_resp = self._head_object(req, version_id)

                # Swift doesn't allow 'if-none-match' to PUT currently.  We
                # have to manually check the returned status code and remove
                # the header manually for now.
                if 'if-none-match' in headers:
                    if src_resp.etag == headers['if-none-match']:
                        raise PreconditionFailed()

                    del headers['if-none-match']

                if version_id:
                    source = '/%s/%s' % self.find_version_object(req,
                                                                 version_id)
                else:
                    source = '/%s/%s' % (req.container_name, req.object_name)

            headers.update({'content-length': 0, 'x-copy-from': source})

            req.version_id = 'null'  # override the source version id

            # TODO: add x-remove-object-meta to drop user metadata

        # set object size
        if req.copy_source is not None:
            # FIXME
            # req.object_size = len(body)
            pass
        else:
            req.object_size = req.content_length

        resp = req.get_response(self.app, 'PUT', headers=headers)

        if resp.status_int == 304:
            # FIXME: should we set source version id here?
            raise PreconditionFailed()

        if req.copy_source is not None and \
                req.metadata_directive == 'REPLACE':
            # TODO: send post_request
            pass

        if req.copy_source is not None:
            resp.last_modified = float(src_resp.object_info['ts'])
            if 'x-amz-version-id' in src_resp.headers:
                resp.headers['x-amz-copy-source-version-id'] = \
                    src_resp.headers['x-amz-version-id']

        return resp

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

        acl = ACL.from_headers(req.headers, bucket_info['acl'].owner,
                               req.user_id)
        if acl is None:
            # FIXME: see ntts ticket #355
            acl = ACLPrivate(bucket_info['acl'].owner, req.user_id)

        req.object_acl = acl

        self.add_version_id(req)

        resp = self._put_object(req)

        if bucket_info['versioning'] is None:
            if 'x-amz-version-id' in resp.headers:
                del resp.headers['x-amz-version-id']
        else:
            resp.headers['x-amz-version-id'] = req.version_id

        if req.copy_source is not None:
            result_elem = Element('CopyObjectResult')
            SubElement(result_elem, 'LastModified').text = \
                resp.last_modified.isoformat()[:-6] + '.000Z'
            SubElement(result_elem, 'ETag').text = resp.etag
            resp.body = tostring(result_elem, use_s3ns=False)
            resp.etag = None

        # FIXME: cleanup
        expiration = self.get_expiration(req, req.object_name,
                                         normalized_currrent_timestamp())
        if expiration:
            resp.headers['x-amz-expiration'] = expiration

        resp.status = 200
        return resp

    def _delete_object(self, req, version_id=None):
        bucket_info = req.get_bucket_info(self.app)

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

    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        bucket_info = req.get_bucket_info(self.app)
        bucket_info['acl'].check_permission(req.user_id, 'WRITE')

        return self._delete_object(req, req.params.get('versionId'))
