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

from swift3.controllers.base import Controller, bucket_owner_required, \
    bucket_operation
from swift3.etree import Element, SubElement, tostring
from swift3.response import InvalidArgument, InvalidRequest, HTTPOk, \
    InvalidBucketState, BucketAlreadyExists
from swift3.subresource import Versioning
from swift3.utils import format_timestamp
from swift3.cfg import CONF


class BucketversionsController(Controller):
    """
    Handles versions requests
    """
    @bucket_operation(err_resp=InvalidRequest,
                      err_msg="There is no such thing as the ?versions "
                      "sub-resource for a key")
    def GET(self, req):
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

        prefix = req.params.get('prefix', '')
        key_marker = req.params.get('key-marker', '')
        version_id_marker = req.params.get('version-id-marker')
        delimiter = req.params.get('delimiter')

        if not key_marker and version_id_marker:
            msg = 'A version-id marker cannot be specified without a key ' \
                'marker.'
            raise InvalidArgument('version-id-marker', version_id_marker, msg)

        is_truncated = False
        versions = []
        common_prefixes = []
        for v in self.versions_iter(req, prefix=prefix,
                                    key_marker=key_marker,
                                    version_id_marker=version_id_marker):
            last_item = v

            # XXX: common prefixes should be handled in generic way.
            if delimiter and delimiter in v['object'][len(prefix):]:
                common_prefix = prefix
                common_prefix += v['object'][len(prefix):].split(delimiter)[0]
                common_prefix += delimiter
                if common_prefix not in common_prefixes:
                    common_prefixes.append(common_prefix)
            else:
                versions.append(v)

            if len(versions) + len(common_prefixes) > max_keys:
                is_truncated = True
                break

        result_elem = Element('ListVersionsResult')
        SubElement(result_elem, 'Name').text = req.container_name

        SubElement(result_elem, 'Prefix').text = prefix
        SubElement(result_elem, 'KeyMarker').text = key_marker

        version_id_marker_elem = SubElement(result_elem, 'VersionIdMarker')
        if version_id_marker is not None:
            version_id_marker_elem.text = version_id_marker

        if is_truncated:
            SubElement(result_elem, 'NextKeyMarker').text = last_item['object']
            SubElement(result_elem, 'NextVersionIdMarker').text = \
                last_item['version_id']

        SubElement(result_elem, 'MaxKeys').text = str(max_keys)

        if delimiter is not None:
            SubElement(result_elem, 'Delimiter').text = delimiter

        if encoding_type is not None:
            SubElement(result_elem, 'EncodingType').text = encoding_type

        SubElement(result_elem, 'IsTruncated').text = \
            'true' if is_truncated else 'false'

        for info in versions:
            if info['delete_marker']:
                version_elem = SubElement(result_elem, 'DeleteMarker')
            else:
                version_elem = SubElement(result_elem, 'Version')
            SubElement(version_elem, 'Key').text = info['object']
            SubElement(version_elem, 'VersionId').text = info['version_id']
            if info['raw_container'].endswith('+versions'):
                SubElement(version_elem, 'IsLatest').text = 'false'
            else:
                SubElement(version_elem, 'IsLatest').text = 'true'
            SubElement(version_elem, 'LastModified').text = \
                format_timestamp(info['ts'])
            if not info['delete_marker']:
                SubElement(version_elem, 'ETag').text = info['etag']
                SubElement(version_elem, 'Size').text = str(info['bytes'])
            owner_elem = SubElement(version_elem, 'Owner')
            SubElement(owner_elem, 'ID').text = info['acl'].owner
            SubElement(owner_elem, 'DisplayName').text = info['acl'].owner
            if not info['delete_marker']:
                SubElement(version_elem, 'StorageClass').text = 'STANDARD'

        for common_prefix in common_prefixes:
            elem = SubElement(result_elem, 'CommonPrefixes')
            SubElement(elem, 'Prefix').text = common_prefix

        xml = tostring(result_elem, encoding_type=encoding_type)

        return HTTPOk(body=xml)


class VersioningController(Controller):
    """
    Handles the following APIs:

     - GET Bucket versioning
     - PUT Bucket versioning

    Those APIs are logged as VERSIONING operations in the S3 server log.
    """
    @bucket_operation
    @bucket_owner_required
    def GET(self, req):
        """
        Handles GET Bucket versioning.
        """
        bucket_info = req.get_bucket_info(self.app)

        versioning = bucket_info['versioning']
        if versioning is None:
            xml = tostring(Element('VersioningConfiguration'))
        else:
            xml = versioning.xml

        return HTTPOk(body=xml)

    @bucket_operation
    @bucket_owner_required
    def PUT(self, req):
        """
        Handles PUT Bucket versioning.
        """
        bucket_info = req.get_bucket_info(self.app)

        if bucket_info['lifecycle'] is not None:
            err_msg = 'Versioning is currently not supported on a bucket ' \
                'with lifecycle configuration. Delete lifecycle ' \
                'configuration before setting versioning for a bucket.'
            raise InvalidBucketState(err_msg)

        req.versioning = req.subresource(Versioning)

        # create a container for version objects
        version_container = req.container_name + '+versions'
        try:
            req.get_response(self.app, container=version_container)
        except BucketAlreadyExists:
            pass

        headers = {'X-Versions-Location': version_container}
        req.get_response(self.app, 'POST', headers=headers)

        return HTTPOk()
