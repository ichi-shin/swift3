# Copyright (c) 2010-2014 OpenStack Foundation.
# Copyright (c) 2013 EVault, Inc.
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

from simplejson import dumps
import os

from swift.common.utils import split_path
from swift.common.swob import HTTPOk, HTTPNoContent

from swift3.controllers.base import Controller
from swift3.response import InvalidArgument, S3ErrorResponse, \
    MalformedXML, InvalidPart, BucketAlreadyExists, InternalError, \
    EntityTooSmall, InvalidPartOrder, InvalidRequest, NotImplemented, \
    AccessDenied
from swift3.utils import unique_id
from swift3.etree import Element, SubElement, fromstring, tostring
from swift3.acl import ACL
from swift3 import utils


def _check_owner_from_upload_id(app, req, upload_id):
    xml = req.get_upload_status(app, upload_id)
    acl = ACL(xml=xml)
    if acl.owner != req.user_id:
        raise AccessDenied()


class PartController(Controller):
    """
    Put upload part controller
    """
    def PUT(self, req):
        if 'uploadId' not in req.params:
            raise InvalidArgument('ResourceType', 'partNumber',
                                  'Unexpected query string parameter')

        try:
            partNumber = int(req.params['partNumber'])
            if partNumber < 1 or utils.MAX_MAX_PARTS < partNumber:
                raise Exception()
        except Exception:
            err_msg = 'Part number must be an integer between 1 and ' \
                '%d, inclusive' % utils.MAX_MAX_PARTS
            raise InvalidArgument('partNumber', req.params['partNumber'],
                                  err_msg)

        upload_id = req.params['uploadId']
        _check_owner_from_upload_id(self.app, req, upload_id)

        container = req.container_name + '+segments'
        obj = '%s/%s/%d' % (req.object_name, upload_id,
                            int(req.params['partNumber']))
        resp = req.put_swift_object(self.app, container=container, obj=obj,
                                    access_check=True)

        if req.copy_source is not None:
            result_elem = Element('CopyPartResult', use_s3ns=False)
            SubElement(result_elem, 'LastModified').text = \
                resp.last_modified.isoformat()[:-6] + '.000Z'
            SubElement(result_elem, 'ETag').text = resp.etag
            resp.body = tostring(result_elem)

        resp.status = 200
        resp.etag = resp.etag  # add '"'
        return resp


class UploadsController(Controller):
    """
    Multipart uploads controller
    """
    def GET(self, req):
        req.check_bucket_owner(self.app)

        if req.object_name:
            err_msg = 'Key is not expected for the GET method' \
                      '?uploads subresource'
            raise InvalidRequest(err_msg)
        encoding_type = req.params.get('encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        keymarker = req.params.get('key-marker', '')
        uploadid = req.params.get('upload-id-marker', '')
        maxuploads = utils.DEFAULT_MAX_UPLOADS
        if 'max-uploads' in req.params:
            try:
                maxuploads = min(maxuploads, int(req.params['max-uploads']))
                if maxuploads < 0:
                    raise Exception()
            except Exception:
                err_msg = 'Provided max-uploads not an integer or within ' \
                    'integer range'
                raise InvalidArgument('max-uploads', req.params['max-uploads'],
                                      err_msg)

        query = {
            'format': 'json',
            'limit': maxuploads + 1,
        }

        base_path = '/'.join([req.tenant_name, req.container_name,
                              req.get_container_ts(self.app)])
        if uploadid and keymarker:
            query.update({'marker': '%s/%s/%s' % (base_path, keymarker,
                                                  uploadid)})
        elif keymarker:
            query.update({'marker': '%s/%s/~' % (base_path, keymarker)})
        if 'prefix' in req.params:
            query.update({'prefix': '%s/%s' % (base_path,
                                               req.params['prefix'])})
        else:
            query.update({'prefix': '%s/' % (base_path)})

        if 'delimiter' in req.params:
            msg = 'delimiter is not supported for list multipart uploads'
            raise NotImplemented(msg)

        resp = req.get_swift_container(self.app, account='.swift3',
                                       container='upload_in_progress',
                                       query=query, access_check=True)

        objects = utils.json_to_objects(resp.body)

        if maxuploads > 0 and len(objects) > maxuploads:
            objects = objects[:maxuploads]
            truncated = True
        else:
            truncated = False

        uploads = []
        prefixes = []
        for o in objects:
            if 'subdir' in o:
                _, _, _, obj, upid = split_path('/' + o['subdir'], 1, 5)
                prefixes.append(obj)
            else:
                _, _, _, obj, upid = split_path('/' + o['name'], 1, 5)
                uploads.append(
                    {'key': obj,
                     'upload_id': upid,
                     'last_modified': o['last_modified']}
                )

        nextkeymarker = ''
        nextuploadmarker = ''
        if len(uploads) > 1:
            nextuploadmarker = uploads[-1]['upload_id']
            nextkeymarker = uploads[-1]['key']

        result_elem = Element('ListMultipartUploadsResult',
                              encoding_type=encoding_type)
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'KeyMarker').text = keymarker
        SubElement(result_elem, 'UploadIdMarker').text = uploadid
        SubElement(result_elem, 'NextKeyMarker').text = nextkeymarker
        SubElement(result_elem, 'NextUploadIdMarker').text = nextuploadmarker
        if 'prefix' in req.params:
            SubElement(result_elem, 'Prefix').text = req.params['prefix']

        SubElement(result_elem, 'MaxUploads').text = maxuploads

        if encoding_type is not None:
            SubElement(result_elem, 'EncodingType').text = encoding_type

        SubElement(result_elem, 'IsTruncated').text = \
            'true' if truncated else 'false'

        for u in uploads:
            upload_elem = SubElement(result_elem, 'Upload')
            SubElement(upload_elem, 'Key').text = u['key']
            SubElement(upload_elem, 'UploadId').text = u['upload_id']
            initiator_elem = SubElement(upload_elem, 'Initiator')
            SubElement(initiator_elem, 'ID').text = req.user_id
            SubElement(initiator_elem, 'DisplayName').text = req.user_id
            owner_elem = SubElement(upload_elem, 'Owner')
            SubElement(owner_elem, 'ID').text = req.user_id
            SubElement(owner_elem, 'DisplayName').text = req.user_id
            SubElement(upload_elem, 'StorageClass').text = 'STANDARD'
            SubElement(upload_elem, 'Initiated').text = \
                u['last_modified'][:-3] + 'Z'

        for p in prefixes:
            elem = SubElement(result_elem, 'CommonPrefixes')
            SubElement(elem, 'Prefix').text = p

        body = tostring(result_elem)

        return HTTPOk(body=body, content_type='application/xml')

    def POST(self, req):
        if not req.object_name:
            raise InvalidRequest('A key must be specified')

        # Create a unique S3 upload id from UUID to avoid duplicates.
        upload_id = unique_id()

        container = req.container_name + '+segments'
        try:
            req.put_swift_container(self.app, container=container)
        except BucketAlreadyExists:
            pass
        req.put_upload_status(self.app, upload_id)

        #
        # Return the S3 response
        #
        result_elem = Element('InitiateMultipartUploadResult')
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = req.object_name
        SubElement(result_elem, 'UploadId').text = upload_id

        body = tostring(result_elem)

        return HTTPOk(body=body, content_type='application/xml')


class UploadController(Controller):
    """
    Handles multipart upload requests

    All the method are passed through so that the s3multi upload helper will
    handle it.
    """
    def GET(self, req):
        encoding_type = req.params.get('encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        uploadId = req.params['uploadId']
        _check_owner_from_upload_id(self.app, req, uploadId)

        maxparts = utils.DEFAULT_MAX_PARTS
        partNumMarker = 0

        if 'max-parts' in req.params:
            try:
                maxparts = int(req.params['max-parts'])
                if maxparts < 1 or utils.MAX_MAX_PARTS < maxparts:
                    raise Exception()
            except Exception:
                err_msg = 'Part number must be an integer between 1 and ' \
                    '%d, inclusive' % utils.MAX_MAX_PARTS
                raise InvalidArgument('partNumber', req.params['max-parts'],
                                      err_msg)

        if 'part-number-marker' in req.params:
            try:
                partNumMarker = int(req.params['part-number-marker'])
            except Exception:
                partNumMarker = 0

        # fetch all upload parts.
        query = {
            'format': 'json',
            'limit': maxparts + 1,
            'prefix': '%s/%s/' % (req.object_name, uploadId),
            'delimiter': '/'
        }

        container = req.container_name + '+segments'
        resp = req.get_swift_container(self.app, query=query,
                                       container=container, access_check=True)
        objects = utils.json_to_objects(resp.body)

        lastPart = 0

        objList = []
        #
        # If the caller requested a list starting at a specific part number,
        # construct a sub-set of the object list.
        #
        if partNumMarker > 0 and len(objects) > 0:
            for o in objects:
                try:
                    num = int(os.path.basename(o['name']))
                except Exception:
                    num = 0
                if num > partNumMarker:
                    objList.append(o)
        else:
            objList = objects

        objList.sort(key=lambda x: int(x['name'].split('/')[-1]))

        if maxparts > 0 and len(objList) == (maxparts + 1):
            truncated = True
        else:
            truncated = False

        if len(objList) > 0:
            o = objList[-1]
            lastPart = os.path.basename(o['name'])

        result_elem = Element('ListPartsResult', encoding_type=encoding_type)
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = req.object_name
        SubElement(result_elem, 'UploadId').text = uploadId

        initiator_elem = SubElement(result_elem, 'Initiator')
        SubElement(initiator_elem, 'ID').text = req.user_id
        SubElement(initiator_elem, 'DisplayName').text = req.user_id
        owner_elem = SubElement(result_elem, 'Owner')
        SubElement(owner_elem, 'ID').text = req.user_id
        SubElement(owner_elem, 'DisplayName').text = req.user_id

        SubElement(result_elem, 'StorageClass').text = 'STANDARD'
        SubElement(result_elem, 'PartNumberMarker').text = partNumMarker
        SubElement(result_elem, 'NextPartNumberMarker').text = lastPart
        SubElement(result_elem, 'MaxParts').text = maxparts
        if 'encoding-type' in req.params:
            SubElement(result_elem, 'EncodingType').text = \
                req.params['encoding-type']
        SubElement(result_elem, 'IsTruncated').text = \
            'true' if truncated else 'false'

        for i in objList[:maxparts]:
            part_elem = SubElement(result_elem, 'Part')
            SubElement(part_elem, 'PartNumber').text = i['name'].split('/')[-1]
            SubElement(part_elem, 'LastModified').text = \
                i['last_modified'][:-3] + 'Z'
            SubElement(part_elem, 'ETag').text = i['hash']
            SubElement(part_elem, 'Size').text = i['bytes']

        body = tostring(result_elem)

        return HTTPOk(body=body, content_type='application/xml')

    def DELETE(self, req):
        uploadId = req.params['uploadId']
        _check_owner_from_upload_id(self.app, req, uploadId)

        #
        # First check to see if this multi-part upload was already
        # completed.  Look in the primary container, if the object exists,
        # then it was completed and we return an error here.
        #
        req.delete_upload_status(self.app, uploadId)

        #
        # The completed object was not found so this
        # must be a multipart upload abort.
        # We must delete any uploaded segments for this UploadID and then
        # delete the object in the main container as well
        #
        query = {
            'format': 'json',
            'limit': utils.MAX_MAX_PARTS,
            'prefix': '%s/%s/' % (req.object_name, uploadId),
            'delimiter': '/',
        }

        container = req.container_name + '+segments'
        resp = req.get_swift_container(self.app, query=query,
                                       container=container)
        #
        #  Iterate over the segment objects and delete them individually
        #
        objects = utils.json_to_objects(resp.body)
        for o in objects:
            container = req.container_name + '+segments'
            req.delete_swift_object(self.app, container=container,
                                    obj=o['name'], access_check=True)

        return HTTPNoContent()

    def POST(self, req):
        uploadId = req.params['uploadId']
        _check_owner_from_upload_id(self.app, req, uploadId)

        xml = req.get_upload_status(self.app, uploadId)
        headers = req.head_upload_status(self.app, uploadId)
        for key, val in headers.iteritems():
            if key.lower().startswith('x-amz-meta-'):
                req.headers['X-Object-Meta-' + key[11:]] = val
        #
        # Query for the objects in the segments area to make sure it completed
        #
        query = {
            'format': 'json',
            'limit': utils.MAX_MAX_PARTS,
            'prefix': '%s/%s/' % (req.object_name, uploadId),
            'delimiter': '/'
        }

        container = req.container_name + '+segments'
        resp = req.get_swift_container(self.app, query=query,
                                       container=container)
        objinfo = utils.json_to_objects(resp.body)
        objtable = dict((o['name'],
                         {'path': '/'.join(['', container, o['name']]),
                          'etag': o['hash'],
                          'size_bytes': o['bytes']}) for o in objinfo)

        # TODO: How AWS S3 handles the case when there are uploaded part
        # objects which are not listed in the body xml?

        manifest = []
        previous_number = 0
        try:
            complete_elem = fromstring(req.body, 'CompleteMultipartUpload')
            for part_elem in complete_elem.iterchildren('Part'):
                part_number = part_elem.find('./PartNumber').text

                if int(part_number) <= int(previous_number):
                    raise InvalidPartOrder(upload_id=uploadId)
                previous_number = part_number

                etag = part_elem.find('./ETag').text
                if len(etag) >= 2 and etag[0] == '"' and etag[-1] == '"':
                    etag = etag[1:-1]

                info = objtable.get("%s/%s/%s" % (req.object_name, uploadId,
                                                  part_number))
                if info is None or info['etag'] != etag:
                    raise InvalidPart(upload_id=uploadId,
                                      part_number=part_number)

                manifest.append(info)
        except S3ErrorResponse:
            raise
        except Exception as e:
            self.logger.exception(e)
            raise MalformedXML()

        req.object_owner = req.user_id
        req.object_timestamp = utils.normalized_currrent_timestamp()
        try:
            resp = req.put_swift_object(self.app, body=dumps(manifest),
                                        query={'multipart-manifest': 'put'},
                                        access_check=True)
        except InternalError as err_resp:
            # FIXME: too hacky
            if hasattr(err_resp, 'sw_resp'):
                sw_resp = err_resp.sw_resp
                err_msg = ''.join(sw_resp['_app_iter'])
                if sw_resp['status_int'] == 400 and \
                        err_msg.startswith('Each segment, except the last, '
                                           'must be at least '):
                    raise EntityTooSmall(err_msg)
            raise

        req.put_s3_acl(self.app, self.logger, xml=xml)
        req.delete_upload_status(self.app, uploadId)

        result_elem = Element('CompleteMultipartUploadResult')
        SubElement(result_elem, 'Location').text = req.host_url + req.path
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = req.object_name
        SubElement(result_elem, 'ETag').text = resp.etag

        resp.body = tostring(result_elem)
        resp.status = 200
        resp.content_type = "application/xml"

        return resp
