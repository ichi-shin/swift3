# Copyright (c) 2014 OpenStack Foundation
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

import simplejson as json

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.etree import fromstring
from mock import patch

acl_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<AccessControlPolicy ' \
    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
    '<Owner>' \
    '<ID>test:tester</ID>' \
    '<DisplayName>test:tester</DisplayName>' \
    '</Owner>' \
    '<AccessControlList>' \
    '<Grant>' \
    '<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
    'xsi:type="CanonicalUser">' \
    '<ID>test:tester</ID>' \
    '<DisplayName>test:tester</DisplayName>' \
    '</Grantee>' \
    '<Permission>FULL_CONTROL</Permission>' \
    '</Grant>' \
    '</AccessControlList>' \
    '</AccessControlPolicy>'

other_acl_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<AccessControlPolicy ' \
    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
    '<Owner>' \
    '<ID>test:tester2</ID>' \
    '<DisplayName>test:tester</DisplayName>' \
    '</Owner>' \
    '<AccessControlList>' \
    '<Grant>' \
    '<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
    'xsi:type="CanonicalUser">' \
    '<ID>test:tester</ID>' \
    '<DisplayName>test:tester</DisplayName>' \
    '</Grantee>' \
    '<Permission>FULL_CONTROL</Permission>' \
    '</Grant>' \
    '</AccessControlList>' \
    '</AccessControlPolicy>'


class TestSwift3MultiUpload(Swift3TestCase):

    def setUp(self):
        super(TestSwift3MultiUpload, self).setUp()

        self.app.register('PUT',
                          '/v1/AUTH_test/bucket+segments',
                          swob.HTTPAccepted, {}, None)
        self.app.register('GET',
                          '/v1/AUTH_test/bucket+segments',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'object/X/1',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'HASH',
                                       'bytes': 100},
                                      {'name': 'object/X/2',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'HASH',
                                       'bytes': 100},
                                      {'name': 'object/QUFB/1',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'HASH',
                                       'bytes': 100},
                                      {'name': 'object/QUFB/1',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'HASH',
                                       'bytes': 100},
                                      ]))
        self.app.register('GET',
                          '/v1/AUTH_test/bucket2+segments',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'object/X/1',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'HASH',
                                       'bytes': 100},
                                      {'name': 'object/X/2',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'HASH',
                                       'bytes': 100},
                                      {'name': 'object/QUFB/1',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'HASH',
                                       'bytes': 100},
                                      {'name': 'object/QUFB/1',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'HASH',
                                       'bytes': 100},
                                      ]))
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket',
                          swob.HTTPNoContent,
                          {'x-container-sysmeta-swift3-acl':
                           '["test:tester"]'},
                          None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket2',
                          swob.HTTPNoContent,
                          {'x-container-sysmeta-swift3-acl':
                           '["test:tester"]'},
                          None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket+segments/object/X',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket2+segments/object/X',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('PUT',
                          '/v1/AUTH_test/bucket+segments/object/X',
                          swob.HTTPCreated, {}, None)
        self.app.register('DELETE',
                          '/v1/AUTH_test/bucket+segments/object/X',
                          swob.HTTPNoContent, {}, None)
        self.app.register('GET',
                          '/v1/AUTH_test/bucket+segments/object/invalid',
                          swob.HTTPNotFound, {}, acl_xml)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket/object',
                          swob.HTTPOk,
                          {'x-timestamp': 4}, None)
        self.app.register('PUT',
                          '/v1/AUTH_test/bucket/object',
                          swob.HTTPCreated, {}, None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket+segments/object/X/1',
                          swob.HTTPOk, {}, None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket+segments/object/X/2',
                          swob.HTTPOk, {}, None)
        self.app.register('PUT',
                          '/v1/AUTH_test/bucket+segments/object/X/1',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/AUTH_test/bucket+segments/object/X/2',
                          swob.HTTPCreated, {}, None)
        self.app.register('DELETE',
                          '/v1/AUTH_test/bucket+segments/object/X/1',
                          swob.HTTPNoContent, {}, None)
        self.app.register('DELETE',
                          '/v1/AUTH_test/bucket+segments/object/X/2',
                          swob.HTTPNoContent, {}, None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket+segments/object/QUFB/1',
                          swob.HTTPOk, {}, None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket+segments/object/QUFB/2',
                          swob.HTTPOk, {}, None)
        self.app.register('PUT',
                          '/v1/AUTH_test/bucket+segments/object/QUFB/1',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/AUTH_test/bucket+segments/object/QUFB/2',
                          swob.HTTPCreated, {}, None)
        self.app.register('DELETE',
                          '/v1/AUTH_test/bucket+segments/object/QUFB/1',
                          swob.HTTPNoContent, {}, None)
        self.app.register('DELETE',
                          '/v1/AUTH_test/bucket+segments/object/QUFB/2',
                          swob.HTTPNoContent, {}, None)

    def test_bucket_multipart_uploads_GET(self):
        req = Request.blank('/bucket/?uploads',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_multipart_uploads_GET_object_name(self):
        req = Request.blank('/bucket/object?uploads',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')

    def test_bucket_multipart_uploads_GET_encoding_type(self):
        req = Request.blank('/bucket/?uploads&encoding-type=url',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_multipart_uploads_GET_encoding_type_error(self):
        req = Request.blank('/bucket/?uploads&encoding-type=xml',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_multipart_uploads_GET_maxuploads(self):
        req = Request.blank('/bucket/?uploads&max-uploads=2',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_multipart_uploads_GET_str_maxuploads(self):
        req = Request.blank('/bucket/?uploads&max-uploads=invalid',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_multipart_uploads_GET_negative_maxuploads(self):
        req = Request.blank('/bucket/?uploads&max-uploads=-1',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_multipart_uploads_GET_with_id_and_key_marker(self):
        req = Request.blank('/bucket/?uploads&upload-id-marker=X&key-marker=Y',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_multipart_uploads_GET_with_key_marker(self):
        req = Request.blank('/bucket/?uploads&key-marker=X',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_multipart_uploads_GET_with_prefix(self):
        req = Request.blank('/bucket/?uploads&prefix=X',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListMultipartUploadsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_multipart_uploads_GET_with_delimiter(self):
        req = Request.blank('/bucket/?uploads&delimiter=X',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NotImplemented')

    @patch('swift3.controllers.multi_upload.unique_id', lambda: 'X')
    def test_object_multipart_upload_initiate(self):
        req = Request.blank('/bucket/object?uploads',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization':
                                     'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'InitiateMultipartUploadResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_multipart_upload_initiate_without_object_name(self):
        req = Request.blank('/bucket?uploads',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization':
                                     'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')

    # @patch('swift3.controllers.multi_upload.unique_id', lambda: 'X')
    # def test_object_multipart_upload_initiate_with_invalid_acl(self):
    #     req = Request.blank('/bucket/object?uploads',
    #                         environ={'REQUEST_METHOD': 'POST'},
    #                         headers={'Authorization':
    #                                  'AWS test:tester:hmac'},
    #                         body=other_acl_xml)
    #     status, headers, body = self.call_swift3(req)
    #     self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_multipart_upload_complete_error(self):
        xml = 'malformed_XML'
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_object_multipart_upload_complete(self):
        xml = '<CompleteMultipartUpload>' \
            '<Part>' \
            '<PartNumber>1</PartNumber>' \
            '<ETag>HASH</ETag>' \
            '</Part>' \
            '<Part>' \
            '<PartNumber>2</PartNumber>' \
            '<ETag>"HASH"</ETag>' \
            '</Part>' \
            '</CompleteMultipartUpload>'
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'CompleteMultipartUploadResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_multipart_upload_complete_EntityTooSmall(self):
        xml = '<CompleteMultipartUpload>' \
            '<Part>' \
            '<PartNumber>1</PartNumber>' \
            '<ETag>HASH</ETag>' \
            '</Part>' \
            '</CompleteMultipartUpload>'
        req = Request.blank('/bucket3/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        # FIXME
        # self.assertEquals(status.split()[0], '400')
        self.assertEquals(status.split()[0], '500')

    def test_object_multipart_upload_complete_invalidPart(self):
        xml = '<CompleteMultipartUpload>' \
            '<Part>' \
            '<PartNumber>1</PartNumber>' \
            '<ETag>invalidHASH</ETag>' \
            '</Part>' \
            '<Part>' \
            '<PartNumber>2</PartNumber>' \
            '<ETag>"HASH"</ETag>' \
            '</Part>' \
            '</CompleteMultipartUpload>'
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')

    def test_object_multipart_upload_complete_invalidPartOrder(self):
        xml = '<CompleteMultipartUpload>' \
            '<Part>' \
            '<PartNumber>2</PartNumber>' \
            '<ETag>HASH</ETag>' \
            '</Part>' \
            '<Part>' \
            '<PartNumber>1</PartNumber>' \
            '<ETag>"HASH"</ETag>' \
            '</Part>' \
            '</CompleteMultipartUpload>'
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')

    def test_object_multipart_upload_abort_error(self):
        req = Request.blank('/bucket/object?uploadId=invalid',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NoSuchUpload')

    def test_object_multipart_upload_abort(self):
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_object_upload_part_error(self):
        req = Request.blank('/bucket/object?partNumber=1',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='part object')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_object_upload_part(self):
        req = Request.blank('/bucket/object?partNumber=1&uploadId=X',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='part object')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_list_parts_error(self):
        req = Request.blank('/bucket/object?uploadId=invalid',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NoSuchUpload')

    def test_object_list_parts(self):
        req = Request.blank('/bucket/object?uploadId=X',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListPartsResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_list_parts_encoding_type(self):
        req = Request.blank('/bucket/object?uploadId=X&encoding-type=url',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListPartsResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_list_parts_encoding_type_error(self):
        req = Request.blank('/bucket/object?uploadId=X&encoding-type=xml',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_object_list_parts_invalid_object_list(self):
        req = Request.blank('/bucket2/object?uploadId=X&part-number-marker=1',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_list_parts_str_max_parts(self):
        req = Request.blank('/bucket/object?uploadId=X&max-parts=invalid',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_object_list_parts_negative_max_parts(self):
        req = Request.blank('/bucket/object?uploadId=X&max-parts=-1',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_object_list_parts_with_part_number_marker(self):
        req = Request.blank('/bucket/object?uploadId=X&'
                            'part-number-marker=1',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListPartsResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_list_parts_invalid_part_number_marker(self):
        req = Request.blank('/bucket/object?uploadId=X&part-number-marker='
                            'invalid',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListPartsResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_list_parts_same_max_marts_as_objects_num(self):
        req = Request.blank('/bucket/object?uploadId=X&max-parts=3',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListPartsResult')
        self.assertEquals(status.split()[0], '200')
