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
from hashlib import md5

from swift.common import swob
from swift.common.swob import Request

from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.request import VersionId
from swift3.etree import fromstring


class TestSwift3MultiDelete(Swift3TestCase):

    def setUp(self):
        super(TestSwift3MultiDelete, self).setUp()

        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'AUTH_test/bucket/0/0',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'},
                                      {'name': 'AUTH_test/marker/0/0',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'}]))
        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules/AUTH_test/bucket/0/0',
                          swob.HTTPNotFound, {}, None)

        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/bucket/0',
                          swob.HTTPNotFound, {}, None)

        self.app.register('HEAD', '/v1/AUTH_test/bucket',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'test:tester',
                           'x-container-meta-[swift3]-versioning-status':
                               'Enabled'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'test:tester'},
                          None)
        self.app.register('GET', '/v1/AUTH_test/bucket+versions?format=json',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'test:tester'},
                          json.dumps([{'name': '004Key1/0000000001.00000',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'},
                                      {'name': '004Key3/0000000001.00000',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'}]))
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions/004Key1/'
                          '0000000001.00000',
                          swob.HTTPOk,
                          {'X-Object-Meta-[Swift3]-Owner': 'test:tester',
                           'x-object-meta-[swift3]-timestamp':
                               '0000000001.00000',
                           'x-object-meta-[swift3]-versioned': 'true'},
                          None)
        self.app.register('DELETE', '/v1/AUTH_test/bucket+versions/004Key1/'
                          '0000000001.00000',
                          swob.HTTPNoContent, {}, None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket/Key1',
                          swob.HTTPOk,
                          {'X-Object-Meta-[Swift3]-Owner': 'test:tester',
                           'x-object-meta-[swift3]-timestamp': 0},
                          None)
        self.app.register('DELETE', '/v1/AUTH_test/bucket/Key1',
                          swob.HTTPNoContent,
                          {'x-object-meta-[swift3]-delete-marker': 'true'},
                          None)
        self.app.register('PUT', '/v1/AUTH_test/bucket/Key1',
                          swob.HTTPCreated,
                          {},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket/Key2',
                          swob.HTTPNotFound,
                          {}, None)
        self.app.register('DELETE', '/v1/AUTH_test/bucket/Key2',
                          swob.HTTPNotFound, {}, None)
        self.app.register('PUT', '/v1/AUTH_test/bucket/Key2',
                          swob.HTTPCreated,
                          {},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions/004Key3/'
                          '0000000001.00000',
                          swob.HTTPOk,
                          {'X-Object-Meta-[Swift3]-Owner': 'test:tester2',
                           'x-object-meta-[swift3]-timestamp':
                               '0000000001.00000',
                           'x-object-meta-[swift3]-versioned': 'true'},
                          None)
        self.app.register('DELETE', '/v1/AUTH_test/bucket+versions/004Key3/'
                          '0000000001.00000',
                          swob.HTTPForbidden, {}, None)
        self.app.register('PUT', '/v1/AUTH_test/bucket/Key3',
                          swob.HTTPCreated,
                          {},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket/Key3',
                          swob.HTTPOk,
                          {'X-Object-Meta-[Swift3]-Owner': 'test:tester2',
                           'x-object-meta-[swift3]-timestamp': 0,
                           'x-object-meta-[swift3]-delete-marker': 'true',
                           'x-object-meta-[swift3]-versioned': 'true'},
                          None)
        self.app.register('PUT', '/v1/AUTH_test/bucket/Key4',
                          swob.HTTPCreated,
                          {},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket/Key4',
                          swob.HTTPOk,
                          {'X-Object-Meta-[Swift3]-Owner': 'test:tester2',
                           'x-object-meta-[swift3]-timestamp': 0,
                           'x-object-meta-[swift3]-delete-marker': 'true'},
                          None)

        conf_xml = '<LifecycleConfiguration>' \
            '  <Rule>' \
            '    <ID>delete-just-after-creation</ID>' \
            '    <Prefix>Key</Prefix>' \
            '    <Status>Enabled</Status>' \
            '    <Expiration>' \
            '      <Days>0</Days>' \
            '    </Expiration>' \
            '  </Rule>' \
            '</LifecycleConfiguration>'

        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules?format=json'
                          '&prefix=AUTH_test/marker/0',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'AUTH_test/marker/0/'
                                       '0000000001.00000',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'}
                                      ]))
        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules/AUTH_test/marker/0/'
                          '0000000001.00000',
                          swob.HTTPOk, {}, conf_xml)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/marker/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('HEAD', '/v1/AUTH_test/marker',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'test:tester',
                           'x-container-meta-[swift3]-versioning-status':
                               'Enabled'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/marker/Key1',
                          swob.HTTPOk,
                          {'x-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': 'test:tester',
                           'x-object-meta-[swift3]-timestamp': 0},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/marker/Key2',
                          swob.HTTPOk,
                          {'x-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': 'test:tester',
                           'x-object-meta-[swift3]-timestamp': 0,
                           'x-object-meta-[swift3]-versioned': 'true'},
                          None)

    def test_object_multi_DELETE_error(self):
        body = 'invalid'
        etag = md5(body).digest().encode('base64')[:-1]
        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': etag},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_object_multi_DELETE_empty_key(self):
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <Delete>\
                  <Quiet>true</Quiet>\
                  <Object>\
                    <Key></Key>\
                  </Object>\
                </Delete>'
        etag = md5(body).digest().encode('base64')[:-1]
        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': etag},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'UserKeyMustBeSpecified')

    def test_object_multi_DELETE_quiet(self):
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <Delete>\
                  <Quiet>true</Quiet>\
                  <Object>\
                    <Key>Key1</Key>\
                  </Object>\
                  <Object>\
                    <Key>Key2</Key>\
                  </Object>\
                  <Object>\
                    <Key>Key3</Key>\
                  </Object>\
                  <Object>\
                    <Key>Key4</Key>\
                  </Object>\
                </Delete>'
        etag = md5(body).digest().encode('base64')[:-1]
        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': etag},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_multi_DELETE(self):
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <Delete>\
                  <Object>\
                    <Key>Key1</Key>\
                  </Object>\
                  <Object>\
                    <Key>Key2</Key>\
                  </Object>\
                  <Object>\
                    <Key>Key3</Key>\
                  </Object>\
                </Delete>'
        etag = md5(body).digest().encode('base64')[:-1]
        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': etag},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'DeleteResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_multi_DELETE_expiration(self):
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <Delete>\
                  <Object>\
                    <Key>Key1</Key>\
                  </Object>\
                  <Object>\
                    <Key>Key2</Key>\
                  </Object>\
                </Delete>'
        etag = md5(body).digest().encode('base64')[:-1]
        req = Request.blank('/marker?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': etag},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'DeleteResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_multi_DELETE_version_id(self):
        version_id = str(VersionId(1))
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <Delete>\
                  <Object>\
                    <Key>Key1</Key>\
                    <VersionId>%s</VersionId>\
                  </Object>\
                  <Object>\
                    <Key>Key2</Key>\
                    <VersionId>%s</VersionId>\
                  </Object>\
                  <Object>\
                    <Key>Key3</Key>\
                    <VersionId>%s</VersionId>\
                  </Object>\
                  <Object>\
                    <Key>Key4</Key>\
                    <VersionId>aaa</VersionId>\
                  </Object>\
                </Delete>' % (version_id, version_id, version_id)
        etag = md5(body).digest().encode('base64')[:-1]
        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': etag},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'DeleteResult')
        self.assertEquals(status.split()[0], '200')

    def test_object_multi_DELETE_with_invalid_md5(self):
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <Delete>\
                  <Object>\
                    <Key>Key1</Key>\
                  </Object>\
                  <Object>\
                    <Key>Key2</Key>\
                  </Object>\
                </Delete>'
        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': 'XXXX'},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidDigest')

    def test_object_multi_DELETE_without_md5(self):
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <Delete>\
                  <Object>\
                    <Key>Key1</Key>\
                  </Object>\
                  <Object>\
                    <Key>Key2</Key>\
                  </Object>\
                </Delete>'
        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_object_multi_DELETE_thousand_key(self):
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <Delete>'
        for key in range(1, 1002):
            body += '<Object>\
                    <Key>Key%s</Key>\
                    </Object>' % key
        body += '</Delete>'
        etag = md5(body).digest().encode('base64')[:-1]
        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': etag},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')
