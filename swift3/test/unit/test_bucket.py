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

from urllib import quote
from mock import patch
import simplejson as json
import cgi

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.etree import fromstring


class TestSwift3Bucket(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Bucket, self).setUp()

        self.objects = (('rose', '2011-01-05T02:19:14.275290', 0, 303),
                        ('viola', '2011-01-05T02:19:14.275290', 0, 3909),
                        ('lily', '2011-01-05T02:19:14.275290', 0, 3909),
                        ('with space', '2011-01-05T02:19:14.275290', 0, 390),
                        ('with%20space', '2011-01-05T02:19:14.275290', 0, 390))

        json_pattern = ['"name":%s', '"last_modified":%s', '"hash":%s',
                        '"bytes":%s']
        json_pattern = '{' + ','.join(json_pattern) + '}'
        json_out = []
        for b in self.objects:
            name = json.dumps(b[0])
            time = json.dumps(b[1])
            json_out.append(json_pattern %
                            (name, time, b[2], b[3]))
        container_list = '[' + ','.join(json_out) + ']'
        container_list_subdir = '[{"subdir":"rose"}, \
                                 {"subdir":"viola"}, \
                                 {"subdir":"lily"}]'
        container_list_delete = '[{"name":"rose",' \
                                '"last_modified":"2011-01-05T02:19:14.2752",' \
                                '"hash":0,"bytes":303}]'
        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'AUTH_test/junk/0/0',
                                       'last_modified':
                                       '1970-01-01T00:00:00.000000',
                                       'hash': 'Y',
                                       'bytes': 'Z'}]))

        conf_xml = '<LifecycleConfiguration>' \
            '  <Rule>' \
            '    <ID>delete-just-after-creation</ID>' \
            '    <Prefix>v</Prefix>' \
            '    <Status>Enabled</Status>' \
            '    <Expiration>' \
            '      <Date>2011-01-01T00:00:00.000Z</Date>' \
            '    </Expiration>' \
            '  </Rule>' \
            '</LifecycleConfiguration>'
        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules/AUTH_test/junk/0/0',
                          swob.HTTPOk, {}, conf_xml)
        self.app.register('GET', '/v1/.swift3/acl/AUTH_test/bucket/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET', '/v1/.swift3/acl/AUTH_test/junk/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET', '/v1/.swift3/acl/AUTH_test/junk_delete/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('PUT', '/v1/.swift3/acl/AUTH_test/bucket/0',
                          swob.HTTPCreated, {}, None)

        self.app.register('HEAD', '/v1/AUTH_test/junk', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Read': 'test:tester',
                           'X-Container-Write': 'test:tester',
                           'x-container-object-count': 1,
                           'x-container-bytes-used': 1,
                           },
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/junk_subdir',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Read': 'test:tester',
                           'X-Container-Write': 'test:tester',
                           'x-container-object-count': 1,
                           'x-container-bytes-used': 1,
                           },
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/junk_delete',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Read': 'test:tester',
                           'X-Container-Write': 'test:tester',
                           'x-container-object-count': 1,
                           'x-container-bytes-used': 1,
                           },
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/junk+123',
                          swob.HTTPNoContent, {}, None)
        self.app.register('GET', '/v1/AUTH_test/junk', swob.HTTPOk, {},
                          container_list)
        for obj, _, _, _ in self.objects:
            self.app.register('HEAD', '/v1/AUTH_test/junk/' + obj,
                              swob.HTTPOk,
                              {'x-object-meta-[swift3]-timestamp': 0,
                               'X-Object-Meta-[Swift3]-Owner': 'test:tester'},
                              None)
        self.app.register('GET', '/v1/AUTH_test/junk_subdir', swob.HTTPOk, {},
                          container_list_subdir)
        self.app.register('GET', '/v1/AUTH_test/junk_delete', swob.HTTPOk, {},
                          container_list_delete)
        self.app.register('HEAD', '/v1/AUTH_test/junk_delete/rose',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': 'test:tester',
                           'x-object-meta-[swift3]-delete-marker': True},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/my_bucket',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'test:tester',
                           'X-Container-Read': 'test:tester',
                           'X-Container-Write': 'test:tester'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/others_bucket',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'test:tester2',
                           'X-Container-Read': 'test:tester2',
                           'X-Container-Write': 'test:tester2'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'test:tester',
                           'X-Container-Read': 'test:tester',
                           'X-Container-Write': 'test:tester'},
                          None)
        self.app.register('PUT', '/v1/AUTH_test/bucket', swob.HTTPCreated,
                          {}, None)
        self.app.register('PUT', '/v1/AUTH_test/my_bucket',
                          swob.HTTPAccepted, {}, None)
        self.app.register('PUT', '/v1/AUTH_test/others_bucket',
                          swob.HTTPAccepted, {}, None)
        self.app.register('POST', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                          {}, None)
        self.app.register('DELETE', '/v1/AUTH_test/bucket',
                          swob.HTTPNoContent, {}, None)

    def test_bucket_HEAD(self):
        req = Request.blank('/junk',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_error(self):
        code = self._test_method_error('GET', '/bucket', swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('GET', '/bucket', swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('GET', '/bucket', swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchBucket')
        code = self._test_method_error('GET', '/bucket', swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_bucket_GET(self):
        bucket_name = 'junk'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.tag, 'ListBucketResult')
        name = elem.find('./Name').text
        self.assertEquals(name, bucket_name)

        objects = elem.iterchildren('Contents')

        names = []
        for o in objects:
            names.append(o.find('./Key').text)
            self.assertTrue(o.find('./LastModified').text.endswith('Z'))

        self.assertEquals(len(names), len(self.objects) - 1)
        for i in self.objects:
            if not i[0] == 'viola':
                self.assertTrue(i[0] in names)

    def test_bucket_GET_subdir(self):
        self.app.register('GET', '/v1/AUTH_test/junk', swob.HTTPOk, {},
                          json.dumps([{'subdir': 'dir'}]))
        bucket_name = 'junk'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_negative_max_keys(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?max-keys=-1' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_GET_invalid_max_keys(self):
        req = Request.blank('/junk?max-keys=invalid',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_GET_is_truncated(self):
        bucket_name = 'junk'

        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET',
                                     'QUERY_STRING': 'max-keys=5'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./IsTruncated').text, 'false')

        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET',
                                     'QUERY_STRING': 'max-keys=4'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./IsTruncated').text, 'true')

    def test_bucket_GET_small_max_keys(self):
        bucket_name = 'junk'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET',
                                     'QUERY_STRING': 'max-keys=5'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./MaxKeys').text, '5')
        paths = [path for method, path in self.app.calls
                 if method == 'GET' and
                 path.startswith('/v1/AUTH_test/junk?')]
        _, query_string = paths[-1].split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assert_(args['limit'] == '6')

    def test_bucket_GET_passthroughs(self):
        bucket_name = 'junk'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET', 'QUERY_STRING':
                                     'delimiter=a&marker=b&prefix=c'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./Prefix').text, 'c')
        self.assertEquals(elem.find('./Marker').text, 'b')
        self.assertEquals(elem.find('./Delimiter').text, 'a')
        paths = [path for method, path in self.app.calls
                 if method == 'GET' and
                 path.startswith('/v1/AUTH_test/junk?')]
        _, query_string = paths[-1].split('?')
        args = dict(cgi.parse_qsl(query_string))
        self.assertEquals(args['delimiter'], 'a')
        self.assertEquals(args['marker'], 'b')
        self.assertEquals(args['prefix'], 'c')

    def test_bucket_GET_with_delimiter_max_keys(self):
        bucket_name = 'junk'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET', 'QUERY_STRING':
                                     'delimiter=a&max-keys=2'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./NextMarker').text, 'viola')
        self.assertEquals(elem.find('./MaxKeys').text, '2')
        self.assertEquals(elem.find('./IsTruncated').text, 'true')

    def test_bucket_GET_subdir_with_delimiter_max_keys(self):
        bucket_name = 'junk_subdir'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET', 'QUERY_STRING':
                                     'delimiter=a&max-keys=2'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./NextMarker').text, 'viola')
        self.assertEquals(elem.find('./MaxKeys').text, '2')
        self.assertEquals(elem.find('./IsTruncated').text, 'true')

    def test_bucket_GET_delete_marker(self):
        bucket_name = 'junk_delete'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET', 'QUERY_STRING':
                                     'delimiter=l'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.find('./IsTruncated').text, 'false')

    def test_bucket_GET_encoding_type(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?encoding-type=url' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body, 'ListBucketResult')
        self.assertEquals(elem.tag, 'ListBucketResult')
        name = elem.find('./Name').text
        self.assertEquals(name, bucket_name)

        objects = elem.iterchildren('Contents')

        names = []
        for o in objects:
            names.append(o.find('./Key').text)
            self.assertTrue(o.find('./LastModified').text.endswith('Z'))

        self.assertEquals(len(names), len(self.objects) - 1)
        for i in self.objects:
            if not i[0] == 'viola':
                self.assertTrue(quote(i[0]) in names)

    def test_bucket_GET_encoding_type_error(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?encoding-type=test' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')

    def test_bucket_GET_bucket_name_error(self):
        bucket_name = 'junk+123'
        req = Request.blank('/%s' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '404')

    def test_bucket_PUT_error(self):
        code = self._test_method_error('PUT', '/bucket', swob.HTTPCreated,
                                       headers={'Content-Length': 'a'})
        self.assertEqual(code, 'InvalidRequest')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPCreated,
                                       headers={'Content-Length': '-1'})
        self.assertEqual(code, 'InvalidRequest')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('PUT', '/bucket', swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_bucket_PUT_overwrite_my_bucket(self):
        req = Request.blank('/my_bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    @patch('swift3.utils.LOCATION', "test")
    def test_bucket_PUT_overwrite_my_bucket_with_other_region(self):
        req = Request.blank('/my_bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '409')

    def test_bucket_PUT_overwrite_others_bucket(self):
        req = Request.blank('/others_bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'BucketAlreadyExists')

    def test_bucket_PUT(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_PUT_with_location(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='<CreateBucketConfiguration '
                                 'xmlns="http://s3.amazonaws.com/doc/'
                                 '2006-03-01/"><LocationConstraint>'
                                 'US</LocationConstraint>'
                                 '</CreateBucketConfiguration >')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_PUT_with_location_error(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='<CreateBucketConfiguration '
                                 'xmlns="http://s3.amazonaws.com/doc/'
                                 '2006-03-01/"><LocationConstraint>'
                                 'test</LocationConstraint>'
                                 '</CreateBucketConfiguration >')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')

    def test_bucket_PUT_with_location_invalid_xml(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='invalid_xml')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_DELETE_error(self):
        code = self._test_method_error('DELETE', '/bucket',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('DELETE', '/bucket', swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('DELETE', '/bucket', swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchBucket')
        code = self._test_method_error('DELETE', '/bucket', swob.HTTPConflict)
        self.assertEquals(code, 'BucketNotEmpty')
        code = self._test_method_error('DELETE', '/bucket',
                                       swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_bucket_DELETE(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_bucket_POST(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NotImplemented')

    def test_bucket_PUT_invalid_name(self):
        req = Request.blank('/bucket+segments',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidBucketName')

    def test_bucket_PUT_with_invalid_acl(self):
        self.app.register('PUT', '/v1/AUTH_test/bucket_error',
                          swob.HTTPInternalServerError, {}, None)
        req = Request.blank('/bucket_error',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'invalid'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')
