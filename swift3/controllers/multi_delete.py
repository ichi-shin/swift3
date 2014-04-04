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

from swift3.controllers.base import Controller, bucket_operation
from swift3.response import NoSuchKey, MalformedXML, ErrorResponse, HTTPOk, \
    UserKeyMustBeSpecified, InvalidArgument, NoSuchVersion
from swift3.etree import Element, SubElement, fromstring, tostring, \
    XMLSyntaxError, DocumentInvalid
from swift3.cfg import CONF
from swift3.controllers.obj import ObjectController
from swift3.utils import LOGGER

MAX_MULTI_DELETE_BODY_SIZE = 61365


class MultiObjectDeleteController(Controller):
    """
    Handles Delete Multiple Objects, which is logged as a MULTI_OBJECT_DELETE
    operation in the S3 server log.
    """
    @bucket_operation
    def POST(self, req):
        """
        Handles Delete Multiple Objects.
        """
        def object_key_iter(xml):
            elem = fromstring(xml, 'Delete')

            quiet = elem.find('./Quiet')
            if quiet is not None and quiet.text.lower() == 'true':
                self.quiet = True

            for obj in elem.iterchildren('Object'):
                key = obj.find('./Key').text
                if not key:
                    raise UserKeyMustBeSpecified()
                version_id = None
                version = obj.find('./VersionId')
                if version is not None:
                    version_id = version.text or ''

                yield key, version_id

        bucket_info = req.get_bucket_info(self.app)
        bucket_info['acl'].check_permission(req.user_id, 'WRITE')

        self.quiet = False

        elem = Element('DeleteResult')

        try:
            xml = req.xml(MAX_MULTI_DELETE_BODY_SIZE, check_md5=True)
            delete_list = list(object_key_iter(xml))
            if len(delete_list) > CONF.max_multi_delete_objects:
                raise MalformedXML()
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except ErrorResponse:
            raise
        except Exception as e:
            LOGGER.error(e)
            raise

        for key, version_id in delete_list:
            delete_marker = None
            try:
                with req.target(req.container_name, key):
                    controller = ObjectController(self.app)
                    controller._delete_object(req, version_id)

                    delete_marker = req.delete_marker
                    if req.version_id:
                        delete_marker_version_id = req.version_id
                    else:
                        delete_marker_version_id = 'null'
            except NoSuchKey:
                pass
            except ErrorResponse as e:
                if version_id is not None and isinstance(e, InvalidArgument):
                    # XXX: The exception is raised because the version is an
                    # invalid id, probably.  In this case, AWS S3 returns
                    # NoSuchVersion error.
                    e = NoSuchVersion(key, version_id)
                error = SubElement(elem, 'Error')
                SubElement(error, 'Key').text = key
                if version_id is not None:
                    SubElement(error, 'VersionId').text = version_id
                SubElement(error, 'Code').text = e.__class__.__name__
                SubElement(error, 'Message').text = e._msg
                continue

            if not self.quiet:
                deleted = SubElement(elem, 'Deleted')
                SubElement(deleted, 'Key').text = key
                if version_id is not None:
                    SubElement(deleted, 'VersionId').text = version_id
                if delete_marker is not None:
                    SubElement(deleted, 'DeleteMarker').text = 'true'
                    SubElement(deleted, 'DeleteMarkerVersionId').text = \
                        delete_marker_version_id

        body = tostring(elem)

        return HTTPOk(body=body)
