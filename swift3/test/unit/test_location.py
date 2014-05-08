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

from mock import patch

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.etree import fromstring


class TestSwift3Location(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Location, self).setUp()

        resp_headers = {
            'x-container-meta-[swift3]-timestamp': '0',
            'X-Container-Meta-[Swift3]-Owner': 'test:tester',
            'X-Container-Read': 'test:tester',
            'X-Container-Write': 'test:tester'
        }

        self.app.register('GET', '/v1/.swift3/acl/AUTH_test/bucket/0',
                          swob.HTTPNotFound, resp_headers, None)
        self.app.register('GET', '/v1/.swift3/acl/AUTH_test/junk/0',
                          swob.HTTPNotFound, resp_headers, None)
        self.app.register('GET', '/v1/.swift3/acl/test:user/junk/0',
                          swob.HTTPNotFound, resp_headers, None)

        self.app.register('HEAD', '/v1/AUTH_test/bucket',
                          swob.HTTPNoContent, resp_headers, None)
        self.app.register('HEAD', '/v1/AUTH_test/junk',
                          swob.HTTPNoContent, resp_headers, None)

    @patch('swift3.utils.LOCATION', 'US-west')
    def test_bucket_location(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?location' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'LocationConstraint')
        self.assertEquals(elem.tag, 'LocationConstraint')
        self.assertEquals(elem.text, 'US-west')

    def test_bucket_location_default(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?location' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'LocationConstraint')
        self.assertEquals(elem.tag, 'LocationConstraint')
        self.assertEquals(elem.text, None)

    def test_bucket_location_head_error(self):
        self.app.register('HEAD', '/v1/AUTH_test/bucket',
                          swob.HTTPUnauthorized, {}, None)
        code = self._test_method_error('GET', '/bucket?location',
                                       swob.HTTPUnauthorized)
        self.assertEquals(code, 'SignatureDoesNotMatch')

    def test_bucket_location_head_not_found(self):
        self.app.register('HEAD', '/v1/AUTH_test/bucket',
                          swob.HTTPNotFound, {}, None)
        code = self._test_method_error('GET', '/bucket?location',
                                       swob.HTTPNotFound)
        self.assertEquals(code, 'NoSuchBucket')

    def test_bucket_location_owner_error(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?location' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:user:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')
