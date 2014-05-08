# Copyright (c) 2014 OpenStack Foundation
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

from datetime import datetime
import simplejson as json

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.request import VersionId
from swift3.etree import fromstring


class TestSwift3Obj(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Obj, self).setUp()

        self.object_body = 'hello'
        self.response_headers = {'Content-Type': 'text/html',
                                 'Content-Length': len(self.object_body),
                                 'x-object-meta-test': 'swift',
                                 'X-Object-Meta-[Swift3]-Missing-Meta': 2,
                                 'X-Object-Meta-[Swift3]-Versioned': 'true',
                                 'X-Object-Meta-[Swift3]-Owner': 'test:tester',
                                 'X-Object-Meta-[swift3]-Timestamp':
                                 '0000000002.00000',
                                 'etag': '1b2cf535f27731c974343645a3985328',
                                 'last-modified':
                                 'Tue, 15 Nov 1994 13:45:26 GMT'}

        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'AUTH_test/bucket/0/0',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'},
                                      {'name': 'AUTH_test/expiration/0/0',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'}]))
        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules/AUTH_test/bucket/0/0',
                          swob.HTTPNotFound, {}, None)

        self.app.register('PUT',
                          '/v1/.swift3/acl',
                          swob.HTTPAccepted, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/bucket/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/bucket/0/object/0',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/versionbucket/0/object/0',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/bucket/0/object/'
                          '0000000002.00000',
                          swob.HTTPCreated, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/bucket/0/object/'
                          '0000000001.00000',
                          swob.HTTPNotFound, {}, None)

        self.app.register('HEAD', '/v1/AUTH_test/some',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('GET', '/v1/AUTH_test/some/source',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'x-object-meta-meta': 'meta',
                           'x-object-meta-[swift3]-missing-meta': 1,
                           'X-Object-Meta-[Swift3]-Owner': 'test:tester'},
                          "copy source")
        self.app.register('GET', '/v1/.swift3/acl/AUTH_test/some/0/source/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET', '/v1/.swift3/acl/AUTH_test/some/0/source/'
                          '0000000001.00000',
                          swob.HTTPNotFound, {}, None)

        self.app.register('HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'test:tester'},
                          None)
        self.app.register('GET', '/v1/AUTH_test/bucket/object',
                          swob.HTTPOk, self.response_headers, self.object_body)
        self.app.register('PUT', '/v1/AUTH_test/bucket/object',
                          swob.HTTPCreated,
                          {'last-modified': 'Mon, 26 May 2014 05:05:55 GMT'},
                          None)
        self.app.register('DELETE', '/v1/AUTH_test/bucket/object',
                          swob.HTTPNoContent, {}, None)

        self.app.register('GET', '/v1/AUTH_test/some+versions?format=json',
                          swob.HTTPOk,
                          {'x-container-meta-[swift3]-timestamp': 0},
                          json.dumps([{'name': '006source/0000000001.00000',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'}]))
        self.app.register('GET', '/v1/AUTH_test/some+versions/006source/'
                          '0000000001.00000',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-owner': 'test:tester',
                           'x-object-meta-[swift3]-timestamp':
                           '0000000001.00000',
                           'x-object-meta-[swift3]-versioned': 'true'},
                          'object with version id')
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('GET', '/v1/AUTH_test/bucket+versions?format=json',
                          swob.HTTPOk,
                          {'x-container-meta-[swift3]-timestamp': 0},
                          json.dumps([{'name': '006object/0000000001.00000',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'}]))
        self.app.register('GET', '/v1/AUTH_test/bucket+versions/006object/'
                          '0000000001.00000',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-owner': 'test:tester',
                           'x-object-meta-[swift3]-timestamp':
                           '0000000001.00000',
                           'x-object-meta-[swift3]-versioned': 'true'},
                          'object with version id')
        self.app.register('DELETE', '/v1/AUTH_test/bucket+versions/006object/'
                          '0000000001.00000',
                          swob.HTTPNoContent, {}, None)
        self.app.register('GET', '/v1/AUTH_test/bucket+versions/006object/'
                          '0000000002.00000',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET', '/v1/AUTH_test/bucket+versions/006object/'
                          '0000000003.00000',
                          swob.HTTPNotFound, {}, None)

        self.app.register('HEAD', '/v1/AUTH_test/versionbucket',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'test:tester',
                           'X-Container-Meta-[Swift3]-Versioning-Status':
                           'Enabled'},
                          None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/versionbucket/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('HEAD', '/v1/AUTH_test/versionbucket/object',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0},
                          None)
        self.app.register('PUT', '/v1/AUTH_test/versionbucket/object',
                          swob.HTTPCreated, {}, None)

        lifecycle_xml = '<LifecycleConfiguration>' \
            '  <Rule>' \
            '    <ID>delete-just-after-creation</ID>' \
            '    <Prefix>obj</Prefix>' \
            '    <Status>Enabled</Status>' \
            '    <Expiration>' \
            '      <Days>0</Days>' \
            '    </Expiration>' \
            '  </Rule>' \
            '</LifecycleConfiguration>'
        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules?format=json'
                          '&prefix=AUTH_test/expiration/0',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'AUTH_test/expiration/0/'
                                       '0000000001.00000',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'}
                                      ]))
        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules/AUTH_test/expiration/0/'
                          '0000000001.00000',
                          swob.HTTPOk, {}, lifecycle_xml)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/expiration/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/expiration/0/object/0',
                          swob.HTTPCreated, {}, None)
        self.app.register('HEAD', '/v1/AUTH_test/expiration', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'test:tester'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/expiration/object',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'x-timestamp': 0},
                          None)
        self.app.register('PUT', '/v1/AUTH_test/expiration/object',
                          swob.HTTPCreated,
                          {'last-modified': 'Mon, 26 May 2014 05:05:55 GMT'},
                          None)

    def _test_object_GETorHEAD(self, method):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        for key, val in self.response_headers.iteritems():
            if key in ('content-length', 'content-type', 'content-encoding',
                       'etag', 'last-modified'):
                self.assertTrue(key in headers)
                self.assertEquals(headers[key], val)

            elif key.startswith('x-object-meta-'):
                self.assertTrue('x-amz-meta-' + key[14:] in headers)
                self.assertEquals(headers['x-amz-meta-' + key[14:]], val)

        self.assertEquals(headers['x-amz-missing-meta'], '2')

        if method == 'GET':
            self.assertEquals(body, self.object_body)

    def test_object_HEAD(self):
        self._test_object_GETorHEAD('HEAD')

    def test_object_HEAD_version_id_latest(self):
        version_id = VersionId(2)
        req = Request.blank('/bucket/object?versionId=' + str(version_id),
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_HEAD_modified_error(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'If-Modified-Since':
                                     'Tue, 15 Nov 1994 14:45:26 GMT'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '304')

    def test_object_HEAD_unmodified_error(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'If-Unmodified-Since':
                                     'Tue, 15 Nov 1994 12:45:26 GMT'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '412')

    def test_object_HEAD_Range(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes=0-3'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '206')

        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '4')

    def test_object_HEAD_Range_minus(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes=-3'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '206')

        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '3')

    def test_object_HEAD_Range_only_min(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes=3-'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '206')

        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '2')

    def test_object_HEAD_Range_only_min_of_over(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes=20-'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '416')

    def test_object_HEAD_Range_without_value(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes=-'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '5')

    def test_object_HEAD_Range_without_equal(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes1-10'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        self.assertTrue('content-length' in headers)
        self.assertEqual(headers['content-length'], '5')

    def test_object_HEAD_Range_error(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes=10-20'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '416')

    def test_object_GET_error(self):
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchKey')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPPreconditionFailed)
        self.assertEquals(code, 'PreconditionFailed')
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_object_GET(self):
        self._test_object_GETorHEAD('GET')

    def test_object_GET_Range(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Range': 'bytes=0-3'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '206')

        self.assertTrue('content-range' in headers)
        self.assertTrue(headers['content-range'].startswith('bytes 0-3'))

    def test_object_GET_Response(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET',
                                     'QUERY_STRING':
                                     'response-content-type=%s&'
                                     'response-content-language=%s&'
                                     'response-expires=%s&'
                                     'response-cache-control=%s&'
                                     'response-content-disposition=%s&'
                                     'response-content-encoding=%s&'
                                     % ('text/plain', 'en',
                                        'Fri, 01 Apr 2014 12:00:00 GMT',
                                        'no-cache',
                                        'attachment',
                                        'gzip')},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        self.assertTrue('content-type' in headers)
        self.assertEquals(headers['content-type'], 'text/plain')
        self.assertTrue('content-language' in headers)
        self.assertEquals(headers['content-language'], 'en')
        self.assertTrue('expires' in headers)
        self.assertEquals(headers['expires'], 'Fri, 01 Apr 2014 12:00:00 GMT')
        self.assertTrue('cache-control' in headers)
        self.assertEquals(headers['cache-control'], 'no-cache')
        self.assertTrue('content-disposition' in headers)
        self.assertEquals(headers['content-disposition'],
                          'attachment')
        self.assertTrue('content-encoding' in headers)
        self.assertEquals(headers['content-encoding'], 'gzip')

    def test_object_GET_if_none_match_error(self):
        code = self._test_method_error('GET', '/bucket/object',
                                       swob.HTTPNotModified)
        self.assertEquals(code, '304 Not Modified')

    def test_object_PUT_error(self):
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchBucket')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPRequestEntityTooLarge)
        self.assertEquals(code, 'EntityTooLarge')
        code = self._test_method_error('PUT', '/bucket/object',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_object_PUT(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'x-amz-storage-class': 'STANDARD',
                     'Content-MD5': 'Gyz1NfJ3Mcl0NDZFo5hTKA=='})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        headers = [h for m, p, h in self.app.calls_with_headers
                   if m == 'PUT' and p == '/v1/AUTH_test/bucket/object'][-1]
        self.assertEquals(headers['etag'], self.response_headers['etag'])

    def test_object_PUT_expiration(self):
        req = Request.blank(
            '/expiration/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'x-amz-storage-class': 'STANDARD',
                     'Content-MD5': 'Gyz1NfJ3Mcl0NDZFo5hTKA=='})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        self.assertIsNotNone(headers['x-amz-expiration'])

    def test_object_PUT_with_versionId(self):
        req = Request.blank(
            '/bucket/object?versionId',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'x-amz-storage-class': 'STANDARD',
                     'Content-MD5': 'Gyz1NfJ3Mcl0NDZFo5hTKA=='})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')

    def test_object_PUT_with_wrong_md5(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'x-amz-storage-class': 'STANDARD',
                     'Content-MD5': 'aa'})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidDigest')

    def test_object_PUT_with_empty_md5(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'x-amz-storage-class': 'STANDARD',
                     'Content-MD5': ''})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidDigest')

    def test_object_PUT_storage_class_error(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'x-amz-storage-class': 'REDUCED_REDUNDANCY',
                     'Content-MD5': 'Gyz1NfJ3Mcl0NDZFo5hTKA=='})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')

    def test_object_PUT_headers(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'STANDARD',
                     'X-Amz-Meta-Something': 'oh hai',
                     'X-Amz-Meta-(invalid)': 'oh hai',
                     'Content-MD5': 'ffoHqOWd280dyE1MT4KuoQ=='},
            body='body')
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        headers = [h for m, p, h in self.app.calls_with_headers
                   if m == 'PUT' and p == '/v1/AUTH_test/bucket/object'][-1]
        self.assertEquals(headers['ETag'], '7dfa07a8e59ddbcd1dc84d4c4f82aea1')
        self.assertEquals(headers['X-Object-Meta-Something'], 'oh hai')
        self.assertEquals(headers['X-Object-Meta-[swift3]-Missing-Meta'], '1')

    def test_object_PUT_copy(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'STANDARD',
                     'X-Amz-Copy-Source': '/some/source'})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'CopyObjectResult')
        self.assertEquals(status.split()[0], '200')
        headers = [h for m, p, h in self.app.calls_with_headers
                   if m == 'PUT' and p == '/v1/AUTH_test/bucket/object'][-1]
        self.assertEquals(headers['X-Object-Meta-Meta'], 'meta')
        self.assertEquals(headers['X-Object-Meta-[Swift3]-Missing-Meta'], '1')
        self.assertEquals(int(headers['Content-Length']), len('copy source'))

    def test_object_PUT_copy_without_slash_prefix(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'STANDARD',
                     'X-Amz-Copy-Source': 'some/source'})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'CopyObjectResult')
        self.assertEquals(status.split()[0], '200')
        headers = [h for m, p, h in self.app.calls_with_headers
                   if m == 'PUT' and p == '/v1/AUTH_test/bucket/object'][-1]
        self.assertEquals(int(headers['Content-Length']), len('copy source'))

    def test_object_PUT_copy_with_content_length(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'STANDARD',
                     'X-Amz-Copy-Source': '/some/source'},
            body='content')
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_object_PUT_copy_to_itself_error(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'STANDARD',
                     'X-Amz-Copy-Source': '/bucket/object'})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_object_PUT_copy_to_itself(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'STANDARD',
                     'X-Amz-Copy-Source': '/bucket/object',
                     'x-amz-metadata-directive': 'REPLACE'})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'CopyObjectResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_copy_from_version_object(self):
        version_id = str(VersionId(1))

        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'STANDARD',
                     'X-Amz-Copy-Source': '/some/source?versionId=%s'
                     % version_id,
                     'x-amz-metadata-directive': 'REPLACE'})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'CopyObjectResult')
        self.assertEquals(status.split()[0], '200')
        headers = [h for m, p, h in self.app.calls_with_headers
                   if m == 'PUT' and p == '/v1/AUTH_test/bucket/object'][-1]
        self.assertEquals(int(headers['Content-Length']),
                          len('object with version id'))

    def test_object_PUT_copy_from_version_object_to_itself(self):
        version_id = str(VersionId(1))

        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'STANDARD',
                     'X-Amz-Copy-Source': '/bucket/object?versionId=%s'
                     % version_id,
                     'x-amz-metadata-directive': 'REPLACE'})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'CopyObjectResult')
        self.assertEquals(status.split()[0], '200')
        headers = [h for m, p, h in self.app.calls_with_headers
                   if m == 'PUT' and p == '/v1/AUTH_test/bucket/object'][-1]
        self.assertEquals(int(headers['Content-Length']),
                          len('object with version id'))

    def test_object_PUT_copy_with_metadata(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Storage-Class': 'STANDARD',
                     'X-Amz-Copy-Source': '/bucket/object',
                     'X-Amz-Copy-Source-if-match': '0',
                     'x-amz-metadata-directive': 'COPY'})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')

    def test_object_DELETE_error(self):
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchKey')
        code = self._test_method_error('DELETE', '/bucket/object',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_object_DELETE(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_object_DELETE_with_version_id(self):
        version_id = str(VersionId(1))

        req = Request.blank('/bucket/object?versionId=' + version_id,
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_object_DELETE_version_id_latest(self):
        version_id = str(VersionId(2))

        req = Request.blank('/bucket/object?versionId=' + version_id,
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_object_GET_with_valid_version_id(self):
        version_id = str(VersionId(1))

        req = Request.blank('/bucket/object?versionId=' + version_id,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_with_invalid_version_id(self):
        req = Request.blank('/bucket/object?versionId=invalid',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

        version_id = 'a/b'
        req = Request.blank('/bucket/object?versionId=' + version_id,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_object_GET_version_id_latest(self):
        version_id = str(VersionId(2))

        req = Request.blank('/bucket/object?versionId=' + version_id,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_version_id_not_found(self):
        version_id = str(VersionId(3))

        req = Request.blank('/bucket/object?versionId=' + version_id,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NoSuchVersion')

    def test_object_PUT_to_versioned_bucket(self):
        req = Request.blank('/versionbucket/object',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='data')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_DELETE_to_versioned_bucket(self):
        req = Request.blank('/versionbucket/object',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='data')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_object_POST(self):
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Authorization': 'AWS test:tester:hmac'})
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MethodNotAllowed')

    def test_object_PUT_with_invalid_acl(self):
        self.app.register('PUT', '/v1/AUTH_test/bucket/object_error',
                          swob.HTTPInternalServerError, {}, None)
        req = Request.blank('/bucket/object_error',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'invalid'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')
