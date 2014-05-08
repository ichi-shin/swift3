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

import simplejson as json

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.etree import fromstring


class TestSwift3Service(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Service, self).setUp()

        self.app.register(
            'GET', '/', swob.HTTPOk, {}, 'passed')
        self.app.register(
            'PUT', '/', swob.HTTPOk, {}, 'passed')

        self.buckets = (('apple', 1, 200), ('orange', 3, 430))

        json_pattern = ['"name":%s', '"count":%s', '"bytes":%s']
        json_pattern = '{' + ','.join(json_pattern) + '}'
        json_out = []
        for b in self.buckets:
            name = json.dumps(b[0])
            json_out.append(json_pattern %
                            (name, b[1], b[2]))
        account_list = '[' + ','.join(json_out) + ']'

        self.app.register('GET', '/v1/AUTH_test', swob.HTTPOk, {},
                          account_list)
        for bucket, _, _ in self.buckets:
            self.app.register('HEAD', '/v1/AUTH_test/' + bucket,
                              swob.HTTPNoContent,
                              {'X-Timestamp': 0,
                               'X-Container-Read': 'test:tester',
                               'X-Container-Write': 'test:tester'}, None)

        self.app.register('GET', '/v1/AUTH_test2', swob.HTTPOk, {},
                          '[{"name":"test+versions", "count": 1, "bytes": 1},' \
                          '{"name":"accessDenied", "count": 2, "bytes": 2},' \
                          '{"name":"noSuchKey", "count": 3, "bytes": 3}]')

        self.app.register('HEAD', '/v1/AUTH_test2/test+versions',
                              swob.HTTPNoContent,
                              {'X-Timestamp': 0,
                               'X-Container-Read': 'test2:tester',
                               'X-Container-Write': 'test2:tester'}, None)

        self.app.register('HEAD', '/v1/AUTH_test2/accessDenied',
                              swob.HTTPForbidden,
                              {'X-Timestamp': 0,
                               'X-Container-Read': 'other:other',
                               'X-Container-Write': 'other:other'}, None)

        self.app.register('HEAD', '/v1/AUTH_test2/noSuchKey',
                              swob.HTTPNotFound, {}, None)

    def test_service_GET_error(self):
        code = self._test_method_error('GET', '/', swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_error('GET', '/', swob.HTTPForbidden)
        self.assertEquals(code, 'AccessDenied')
        code = self._test_method_error('GET', '/', swob.HTTPServiceUnavailable)
        self.assertEquals(code, 'ServiceUnavailable')
        code = self._test_method_error('GET', '/', swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def _test_method_service_GET_head_error(self, method, path, resp_cls,
                                            headers=None):
        if headers is None:
            headers = {}
        for bucket, _, _ in self.buckets:
            self.app.register('HEAD', '/v1/AUTH_test/' + bucket,
                              resp_cls,
                              {'X-Timestamp': '0'}, None)

        headers.update({'Authorization': 'AWS test:tester:hmac'})
        req = Request.blank(path, environ={'REQUEST_METHOD': method},
                            headers=headers)
        status, headers, body = self.call_swift3(req)
        elem = fromstring(body, 'Error')
        if elem.tag == 'Error':
            return elem.find('./Code').text
        return status.split()[0]

    def test_service_GET_container_head_error(self):
        code = self._test_method_service_GET_head_error('GET', '/',
                                                        swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')
        code = self._test_method_service_GET_head_error('GET', '/',
                                                        swob.HTTPServerError)
        self.assertEquals(code, 'InternalError')

    def test_service_GET(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body, 'ListAllMyBucketsResult')
        self.assertEquals(elem.tag, 'ListAllMyBucketsResult')

        all_buckets = elem.find('./Buckets')
        buckets = all_buckets.iterchildren('Bucket')
        listing = list(list(buckets)[0])
        self.assertEquals(len(listing), 2)

        names = []
        for b in all_buckets.iterchildren('Bucket'):
            names.append(b.find('./Name').text)

        self.assertEquals(len(names), len(self.buckets))
        for i in self.buckets:
            self.assertTrue(i[0] in names)

    def test_service_GET_invalid_bucket(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test2:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body, 'ListAllMyBucketsResult')
        self.assertEquals(elem.tag, 'ListAllMyBucketsResult')

    def test_bucket_owner_with_only_acl(self):
        # container_name -> (write_acl, read_acl)
        containers = {
            'mine1': ('test:tester,test:other',
                      'test:other,test:tester'),
            'mine2': ('test:tester,test:other',
                      '.r:*'),
            'mine3': ('test:other,test:tester',
                      'test:tester'),
            'other1': ('test:other,test:tester',
                       'test:tester,test:other'),
            'other2': ('test:other',
                       '.r:*'),
            'other3': ('test:tester',
                       ''),
            'other4': ('test:tester',
                       'test:other'),
        }
        json_out = []
        for name in containers:
            json_out.append({'name': name, 'count': '0', 'bytes': '0'})

            write_acl, read_acl = containers[name]
            self.app.register('HEAD', '/v1/AUTH_test/' + name,
                              swob.HTTPNoContent,
                              {'X-Timestamp': 0,
                               'X-Container-Write': write_acl,
                               'X-Container-Read': read_acl}, None)
        self.app.register('GET', '/v1/AUTH_test',
                          swob.HTTPOk, {}, json.dumps(json_out))

        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

        elem = fromstring(body, 'ListAllMyBucketsResult')
        self.assertEquals(elem.tag, 'ListAllMyBucketsResult')

        all_buckets = elem.find('./Buckets')
        names = []
        for b in all_buckets.iterchildren('Bucket'):
            names.append(b.find('./Name').text)

        correct = ['mine1', 'mine2', 'mine3']
        self.assertEquals(len(names), len(correct))
        for name in names:
            self.assertTrue(name in correct)
