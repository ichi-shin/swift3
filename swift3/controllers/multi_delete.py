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
from swift3.response import NoSuchKey, MalformedXML, S3ErrorResponse, \
    UserKeyMustBeSpecified, InvalidArgument, NoSuchVersion
from swift3.etree import Element, SubElement, fromstring, tostring
from swift3 import utils


class MultiObjectDeleteController(Controller):
    """
    Handles Multi Delete Object requests
    """
    def POST(self, req):
        def object_key_iter(xml):
            elem = fromstring(xml, 'Delete')

            quiet_elem = elem.find('./Quiet')
            if quiet_elem is not None and quiet_elem.text.lower() == 'true':
                self.quiet = True

            for obj_elem in elem.iterchildren('Object'):
                key = obj_elem.find('./Key').text
                if not key:
                    raise UserKeyMustBeSpecified()
                version = None
                version_elem = obj_elem.find('./VersionId')
                if version_elem is not None:
                    version = version_elem.text or ''

                yield key, version

        req.head_swift_container(self.app)

        self.quiet = False

        delete_result_elem = Element('DeleteResult')

        try:
            delete_list = list(object_key_iter(req.body))
            if len(delete_list) > utils.MAX_MULTI_DELETE_OBJECTS:
                raise MalformedXML()
        except S3ErrorResponse:
            raise
        except Exception:
            raise MalformedXML()

        req.check_md5()

        base_container_name = req.container_name
        for key, version in delete_list:
            h_resp = None
            try:
                req.container_name = base_container_name
                if version is None:
                    req.object_name = key
                    v_check = True
                else:
                    container, obj = req.find_version_object(self.app, key,
                                                             version)
                    req.container_name = container
                    req.object_name = obj
                    v_check = False

                # HEAD object to check delete marker
                h_resp = req.head_swift_object(self.app)
                resp = req.delete_swift_object(self.app, access_check=True,
                                               versioning_check=v_check)

                delete_marker = req.delete_marker
                if resp.headers['x-amz-version-id']:
                    delete_marker_version_id = resp.headers['x-amz-version-id']
                else:
                    delete_marker_version_id = 'null'
            except NoSuchKey:
                if h_resp:
                    delete_marker = h_resp.delete_marker
                    if h_resp.versioned:
                        from swift3.request import VersionId
                        ts = h_resp.object_timestamp
                        delete_marker_version_id = str(VersionId(ts))
                    else:
                        delete_marker_version_id = 'null'
                else:
                    delete_marker = None
            except S3ErrorResponse as e:
                if version is not None and isinstance(e, InvalidArgument):
                    # XXX: The exception is raised because the version is an
                    # invalid id, probably.  In this case, AWS S3 returns
                    # NoSuchVersion error.
                    e = NoSuchVersion(key, version)
                error_elem = SubElement(delete_result_elem, 'Error')
                SubElement(error_elem, 'Key').text = key
                if version is not None:
                    SubElement(error_elem, 'VersionId').text = version
                SubElement(error_elem, 'Code').text = e.__class__.__name__
                SubElement(error_elem, 'Message').text = e._msg
                continue

            if not self.quiet:
                deleted_elem = SubElement(delete_result_elem, 'Deleted')
                SubElement(deleted_elem, 'Key').text = key
                if version is not None:
                    SubElement(deleted_elem, 'VersionId').text = version
                if delete_marker is not None:
                    SubElement(deleted_elem, 'DeleteMarker').text = 'true'
                    SubElement(deleted_elem, 'DeleteMarkerVersionId').text = \
                        delete_marker_version_id

        return HTTPOk(body=tostring(delete_result_elem))
