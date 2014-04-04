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

from swift3.controllers.base import Controller, bucket_owner_required
from swift3.response import InvalidArgument, S3NotImplemented, \
    BucketAlreadyExists, NoSuchKey, InvalidLocationConstraint, \
    MalformedXML, HTTPOk, HTTPNoContent
from swift3.subresource import ACL, ACLPrivate
from swift3.etree import Element, SubElement, tostring, fromstring, \
    XMLSyntaxError, DocumentInvalid
from swift3.utils import LOGGER, json_to_objects, format_timestamp, \
    normalized_currrent_timestamp
from swift3.cfg import CONF

MAX_PUT_BUCKET_BODY_SIZE = 10240


class BucketController(Controller):
    """
    Handles bucket request.
    """
    def HEAD(self, req):
        """
        Handle HEAD Bucket (Get Metadata) request
        """
        resp = req.get_response(self.app)
        resp.bucket_info['acl'].check_permission(req.user_id, 'READ')

        return HTTPOk(headers=resp.headers)

    def GET(self, req):
        """
        Handle GET Bucket (List Objects) request
        """
        max_keys = CONF.default_max_bucket_listing
        if 'max-keys' in req.params:
            try:
                max_keys = int(req.params['max-keys'])
                if max_keys < 0 or CONF.max_max_bucket_listing < max_keys:
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

        resp = req.get_response(self.app, query=query)
        resp.bucket_info['acl'].check_permission(req.user_id, 'READ')

        objects = json_to_objects(resp.body)

        elem = Element('ListBucketResult')
        SubElement(elem, 'Name').text = req.container_name
        SubElement(elem, 'Prefix').text = req.params.get('prefix')
        SubElement(elem, 'Marker').text = req.params.get('marker')

        is_truncated = max_keys > 0 and len(objects) >= (max_keys + 1)

        if is_truncated and 'delimiter' in req.params:
            if 'name' in objects[max_keys - 1]:
                SubElement(elem, 'NextMarker').text = \
                    objects[max_keys - 1]['name']
            if 'subdir' in objects[max_keys - 1]:
                SubElement(elem, 'NextMarker').text = \
                    objects[max_keys - 1]['subdir']

        SubElement(elem, 'MaxKeys').text = str(max_keys)

        if 'delimiter' in req.params:
            SubElement(elem, 'Delimiter').text = req.params['delimiter']

        if encoding_type is not None:
            SubElement(elem, 'EncodingType').text = encoding_type

        SubElement(elem, 'IsTruncated').text = \
            'true' if is_truncated else 'false'

        for o in objects[:max_keys]:
            if 'subdir' not in o:
                try:
                    object_info = req.get_object_info(self.app, obj=o['name'])

                    if object_info['delete_marker']:
                        continue

                except NoSuchKey:
                    # the object was expired
                    continue

                contents = SubElement(elem, 'Contents')
                SubElement(contents, 'Key').text = o['name']
                SubElement(contents, 'LastModified').text = \
                    format_timestamp(object_info['ts'])
                SubElement(contents, 'ETag').text = o['hash']
                SubElement(contents, 'Size').text = str(o['bytes'])
                owner = SubElement(contents, 'Owner')
                SubElement(owner, 'ID').text = object_info['acl'].owner
                SubElement(owner, 'DisplayName').text = \
                    object_info['acl'].owner
                SubElement(contents, 'StorageClass').text = 'STANDARD'

        for o in objects[:max_keys]:
            if 'subdir' in o:
                common_prefixes = SubElement(elem, 'CommonPrefixes')
                SubElement(common_prefixes, 'Prefix').text = o['subdir']

        body = tostring(elem, encoding_type=encoding_type)

        return HTTPOk(body=body, content_type='application/xml')

    def PUT(self, req):
        """
        Handle PUT Bucket request
        """
        xml = req.xml(MAX_PUT_BUCKET_BODY_SIZE)
        if xml:
            # check location
            try:
                elem = fromstring(xml, 'CreateBucketConfiguration')
                location = elem.find('./LocationConstraint').text
            except (XMLSyntaxError, DocumentInvalid):
                raise MalformedXML()
            except Exception as e:
                LOGGER.error(e)
                raise

            if location != CONF.location:
                # Swift3 cannot support multiple reagions now.
                raise InvalidLocationConstraint()

        try:
            acl = ACL.from_headers(req.headers, req.user_id)
            if acl is None:
                acl = ACLPrivate(req.user_id)

            req.get_response(self.app)
            # update metadata
            req.bucket_timestamp = normalized_currrent_timestamp()
            req.bucket_acl = acl
            headers = {
                'X-Container-Read': req.user_id,
                'X-Container-Write': req.user_id,
            }
            req.get_response(self.app, 'POST', headers=headers)
        except BucketAlreadyExists as e:
            # s3 returns HTTPOk if the target bucket is mine and CONF.location
            # is the default location.
            bucket_info = req.get_bucket_info(self.app)
            if bucket_info['acl'].owner == req.user_id and \
                    (not CONF.location or CONF.location == 'US'):
                pass
            else:
                raise e

        resp = HTTPOk()
        resp.location = '/' + req.container_name

        return resp

    @bucket_owner_required
    def DELETE(self, req):
        """
        Handle DELETE Bucket request
        """
        req.get_response(self.app)

        return HTTPNoContent()

    def POST(self, req):
        """
        Handle POST Bucket request
        """
        raise S3NotImplemented()
