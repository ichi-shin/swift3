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
from swift3.etree import Element, SubElement, tostring
from swift3.response import InvalidArgument, InvalidRequest
from swift3 import utils


class BucketversionsController(Controller):
    """
    Handles versions requests
    """
    def GET(self, req):
        if req.object_name:
            raise InvalidRequest('There is no such thing as the ?versions '
                                 'sub-resource for a key')

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

        prefix = req.params.get('prefix', '')
        key_marker = req.params.get('key-marker', '')
        version_id_marker = req.params.get('version-id-marker')
        delimiter = req.params.get('delimiter')

        versions = req.collect_versions(self.app)
        versions = [v for v in versions if v[0].startswith(prefix)]
        if version_id_marker is not None:
            versions = [v for v in versions if v[0] > key_marker or
                        v[0] == key_marker and v[1] > version_id_marker]
        else:
            versions = [v for v in versions if v[0] > key_marker]

        version_result = []
        for v in versions:
            key = v[0]
            if delimiter and delimiter in key[len(prefix):]:
                common_prefix = prefix
                common_prefix += key[len(prefix):].split(delimiter)[0]
                common_prefix += delimiter
                if common_prefix not in version_result:
                    version_result.append(common_prefix)
            else:
                version_result.append(v)

        if len(version_result) > max_keys:
            version_result = version_result[:max_keys]
            is_truncated = True
        else:
            is_truncated = False

        result_elem = Element('ListVersionsResult',
                              encoding_type=encoding_type)
        SubElement(result_elem, 'Name').text = req.container_name

        SubElement(result_elem, 'Prefix').text = prefix
        SubElement(result_elem, 'KeyMarker').text = key_marker

        version_id_marker_elem = SubElement(result_elem, 'VersionIdMarker')
        if version_id_marker is not None:
            version_id_marker_elem.text = version_id_marker

        if is_truncated:
            v = version_result[-1]
            SubElement(result_elem, 'NextKeyMarker').text = v[0]
            if len(v) > 1:
                SubElement(result_elem, 'NextVersionIdMarker').text = v[1]

        SubElement(result_elem, 'MaxKeys').text = str(max_keys)

        if delimiter is not None:
            SubElement(result_elem, 'Delimiter').text = delimiter

        if encoding_type is not None:
            SubElement(result_elem, 'EncodingType').text = encoding_type

        SubElement(result_elem, 'IsTruncated').text = \
            'true' if is_truncated else 'false'

        for key, v_id, delete, is_latest, lmodified, etag, size, owner \
                in (v for v in version_result if isinstance(v, tuple)):
            if delete:
                version_elem = SubElement(result_elem, 'DeleteMarker')
            else:
                version_elem = SubElement(result_elem, 'Version')
            SubElement(version_elem, 'Key').text = key
            SubElement(version_elem, 'VersionId').text = v_id
            SubElement(version_elem, 'IsLatest').text = is_latest
            SubElement(version_elem, 'LastModified').text = \
                lmodified[:-3] + 'Z'
            if not delete:
                SubElement(version_elem, 'ETag').text = etag
                SubElement(version_elem, 'Size').text = str(size)
            owner_elem = SubElement(version_elem, 'Owner')
            SubElement(owner_elem, 'ID').text = owner
            SubElement(owner_elem, 'DisplayName').text = owner
            if not delete:
                SubElement(version_elem, 'StorageClass').text = 'STANDARD'

        for common_prefix in (v for v in version_result if isinstance(v, str)):
            elem = SubElement(result_elem, 'CommonPrefixes')
            SubElement(elem, 'Prefix').text = common_prefix

        xml = tostring(result_elem)

        return HTTPOk(body=xml)


class VersioningController(Controller):
    """
    Handles versioning requests
    """
    def GET(self, req):
        req.check_bucket_owner(self.app)
        xml = req.get_versioning(self.app)

        return HTTPOk(body=xml)

    def PUT(self, req):
        req.check_bucket_owner(self.app)
        req.put_versioning(self.app)

        return HTTPOk()
