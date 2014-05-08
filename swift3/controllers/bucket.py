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

from swift.common.swob import HTTPOk, HTTPNoContent

from swift3.controllers.base import Controller
from swift3.response import InvalidArgument, NotImplemented, \
    BucketAlreadyExists, NoSuchKey, InvalidLocationConstraint, \
    MalformedXML, BucketAlreadyOwnedByYou
from swift3 import utils
from swift3.etree import Element, SubElement, tostring, fromstring
from swift3.acl import ACL, AllUsers


class BucketController(Controller):
    """
    Handles bucket request.
    """
    def HEAD(self, req):
        """
        Handle HEAD Bucket (Get Metadata) request
        """
        resp = req.head_swift_container(self.app, access_check=True)
        headers = resp.headers

        if 'x-container-object-count' in resp.sw_headers:
            headers['x-rgw-object-count'] = \
                resp.sw_headers['x-container-object-count']
        if 'x-container-bytes-used' in resp.sw_headers:
            headers['x-rgw-bytes-used'] = \
                resp.sw_headers['x-container-bytes-used']

        return HTTPOk(headers=headers, app_iter=resp.app_iter)

    def GET(self, req):
        """
        Handle GET Bucket (List Objects) request
        """
        max_keys = utils.DEFAULT_MAX_BUCKET_LISTING
        if 'max-keys' in req.params:
            try:
                max_keys = int(req.params['max-keys'])
                if max_keys < 0 or utils.MAX_MAX_BUCKET_LISTING < max_keys:
                    raise Exception()
            except Exception:
                err_msg = 'Provided max-keys not an integer or within ' \
                    'integer range'
                raise InvalidArgument('max-keys', req.params['max-keys'],
                                      err_msg)

        encoding_type = req.params.get('encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        query = {
            'format': 'json',
            'limit': max_keys + 1,
        }
        if 'marker' in req.params:
            query.update({'marker': req.params['marker']})
        if 'prefix' in req.params:
            query.update({'prefix': req.params['prefix']})
        if 'delimiter' in req.params:
            query.update({'delimiter': req.params['delimiter']})

        resp = req.get_swift_container(self.app, query=query,
                                       access_check=True)

        objects = utils.json_to_objects(resp.body)

        result_elem = Element('ListBucketResult', encoding_type=encoding_type)
        SubElement(result_elem, 'Name').text = req.container_name

        SubElement(result_elem, 'Prefix').text = req.params.get('prefix')
        SubElement(result_elem, 'Marker').text = req.params.get('marker')

        is_truncated = max_keys > 0 and len(objects) >= (max_keys + 1)

        if is_truncated and 'delimiter' in req.params:
            if 'name' in objects[max_keys - 1]:
                SubElement(result_elem, 'NextMarker').text = \
                    objects[max_keys - 1]['name']
            if 'subdir' in objects[max_keys - 1]:
                SubElement(result_elem, 'NextMarker').text = \
                    objects[max_keys - 1]['subdir']

        SubElement(result_elem, 'MaxKeys').text = max_keys

        if 'delimiter' in req.params:
            SubElement(result_elem, 'Delimiter').text = req.params['delimiter']

        if encoding_type is not None:
            SubElement(result_elem, 'EncodingType').text = encoding_type

        SubElement(result_elem, 'IsTruncated').text = \
            'true' if is_truncated else 'false'

        for i in objects[:max_keys]:
            if 'subdir' in i:
                elem = SubElement(result_elem, 'CommonPrefixes')
                SubElement(elem, 'Prefix').text = i['subdir']
            else:
                try:
                    sub_resp = req.head_swift_object(self.app, obj=i['name'])

                    if sub_resp.delete_marker:
                        continue

                    req.check_expiration(self.app, i['name'], sub_resp)
                except NoSuchKey:
                    # the object was expired
                    continue

                contents = SubElement(result_elem, 'Contents')
                SubElement(contents, 'Key').text = i['name']
                SubElement(contents, 'LastModified').text = \
                    i['last_modified'][:-3] + 'Z'
                SubElement(contents, 'ETag').text = i['hash']
                SubElement(contents, 'Size').text = i['bytes']
                owner = SubElement(contents, 'Owner')
                SubElement(owner, 'ID').text = sub_resp.object_owner
                SubElement(owner, 'DisplayName').text = sub_resp.object_owner
                SubElement(contents, 'StorageClass').text = 'STANDARD'

        body = tostring(result_elem)
        return HTTPOk(body=body, content_type='application/xml')

    def PUT(self, req):
        """
        Handle PUT Bucket request
        """
        headers = {}

        if req.body:
            # check location
            try:
                elem = fromstring(req.body, 'CreateBucketConfiguration')
                loc = elem.find('./LocationConstraint').text
            except Exception as e:
                self.logger.error(e)
                raise MalformedXML()

            if loc != utils.LOCATION:
                raise InvalidLocationConstraint()

        try:
            acl = ACL(headers=req.headers)
            if not utils.ALLOW_CONTAINER_PUBLIC_WRITE:
                for p, g in acl:
                    if p in ['WRITE', 'FULL_CONTROL'] \
                       and isinstance(g, AllUsers):
                        raise InvalidArgument('ACL', p,
                                              'Unsupported ACL for AllUsers')

            req.put_swift_container(self.app)
            # update metadata
            req.bucket_timestamp = utils.normalized_currrent_timestamp()
            headers['X-Container-Read'] = req.user_id
            headers['X-Container-Write'] = req.user_id

            req.post_swift_container(self.app, headers=headers)

            req.put_s3_acl(self.app, self.logger, xml=acl.to_xml(req.user_id))
        except BucketAlreadyExists as e:
            # s3 returns HTTPOk if the target bucket is mine
            r = req.head_swift_container(self.app)
            if r.bucket_owner == req.user_id:
                if not utils.LOCATION or utils.LOCATION == 'US':
                    pass
                else:
                    raise BucketAlreadyOwnedByYou(req.container_name)
            else:
                raise e

        return HTTPOk(headers={'Location': '/' + req.container_name})

    def DELETE(self, req):
        """
        Handle DELETE Bucket request
        """
        req.check_bucket_owner(self.app)
        req.delete_swift_container(self.app, access_check=True)

        return HTTPNoContent()

    def POST(self, req):
        """
        Handle POST Bucket request
        """
        raise NotImplemented()
