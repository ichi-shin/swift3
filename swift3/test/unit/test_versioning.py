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

versioning_xml_fmt = '<VersioningConfiguration ' \
    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
    '<Status>%s</Status>' \
    '</VersioningConfiguration>'

error_versioning_xml = '<VersioningConfiguration ' \
    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
    '</VersioningConfiguration>'

lifecycle_conf_xml = '<LifecycleConfiguration>' \
    '  <Rule>' \
    '    <Prefix>a</Prefix>' \
    '    <Status>Enabled</Status>' \
    '    <Expiration>' \
    '      <Days>0</Days>' \
    '    </Expiration>' \
    '  </Rule>' \
    '</LifecycleConfiguration>'


class TestSwift3Versioning(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Versioning, self).setUp()

        self.app.register('HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                          {'x-container-sysmeta-swift3-acl': '["test:tester"]',
                           'x-container-sysmeta-swift3-versioning':
                               '"Enabled"',
                           'x-timestamp': '0'}, None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/lifecycled',
                          swob.HTTPNoContent,
                          {'x-container-sysmeta-swift3-acl': '["test:tester"]',
                           'x-container-sysmeta-swift3-lifecycle':
                           '[["id","prefix",1,"",1]]'},
                          None)
        self.app.register('PUT', '/v1/AUTH_test/bucket', swob.HTTPCreated,
                          {}, None)
        self.app.register('POST', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                          {}, None)
        self.app.register('PUT', '/v1/AUTH_test/bucket+versions',
                          swob.HTTPAccepted, {}, None)

        self.app.register('GET', '/v1/AUTH_test/bucket/delete-marker',
                          swob.HTTPOk,
                          {'x-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Delete-Marker': 'true'},
                          "delete_marker")
        self.app.register('PUT', '/v1/AUTH_test/bucket/delete-marker',
                          swob.HTTPCreated,
                          {'x-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Delete-Marker': 'true'},
                          None)
        old_versions = {
            '004obj1': [
                {
                    'name': '004obj1/0000000001.00000',
                    'last_modified':
                        '2014-05-07T19:47:54.592270',
                    'hash': 'Y',
                    'bytes': 1,
                }, {
                    'name': '004obj1/0000000002.00000',
                    'last_modified':
                        '2014-05-07T19:47:54.592270',
                    'hash': 'Y',
                    'bytes': 1,
                },
            ],
            '004obj2': [
                {
                    'name': '004obj2/0000000001.00000',
                    'last_modified':
                        '2014-05-07T19:47:54.592270',
                    'hash': 'Y',
                    'bytes': 1,
                }, {
                    'name': '004obj2/0000000002.00000',
                    'last_modified':
                        '2014-05-07T19:47:54.592270',
                    'hash': 'Y',
                    'bytes': 1,
                },
            ],
            '004obj3': [
            ],
            '01ephotos/2006/January/sample.jpg': [
                {
                    'name':
                        '01ephotos/2006/January/sample.jpg/0000000001.00000',
                    'last_modified':
                        '2014-05-07T19:47:54.592270',
                    'hash': 'Y',
                    'bytes': 1,
                },
            ],
            '01fphotos/2006/February/sample.jpg': [
                {
                    'name':
                        '01fphotos/2006/February/sample.jpg/0000000001.00000',
                    'last_modified':
                        '2014-05-07T19:47:54.592270',
                    'hash': 'Y',
                    'bytes': 1,
                },
            ],
            '01cphotos/2006/March/sample.jpg': [
                {
                    'name': '01cphotos/2006/March/sample.jpg/0000000001.00000',
                    'last_modified':
                        '2014-05-07T19:47:54.592270',
                    'hash': 'Y',
                    'bytes': 1,
                },
            ],
            '01cvideos/2006/March/sample.wmv': [
                {
                    'name': '01cvideos/2006/March/sample.wmv/0000000001.00000',
                    'last_modified':
                        '2014-05-07T19:47:54.592270',
                    'hash': 'Y',
                    'bytes': 1,
                },
            ],
            '00asample.jpg': [
                {
                    'name': '00asample.jpg/0000000001.00000',
                    'last_modified':
                        '2014-05-07T19:47:54.592270',
                    'hash': 'Y',
                    'bytes': 1,
                }
            ],
        }
        latest_versions = [
            {
                'name': 'obj1',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }, {
                'name': 'obj2',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }, {
                'name': 'obj3',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }, {
                'name': 'photos/2006/January/sample.jpg',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }, {
                'name': 'photos/2006/February/sample.jpg',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }, {
                'name': 'photos/2006/March/sample.jpg',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }, {
                'name': 'videos/2006/March/sample.wmv',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }, {
                'name': 'sample.jpg',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }
        ]
        latest_versions_obj = [
            {
                'name': 'obj1',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }, {
                'name': 'obj2',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }, {
                'name': 'obj3',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }
        ]
        latest_versions_photos_2006 = [
            {
                'name': 'photos/2006/January/sample.jpg',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }, {
                'name': 'photos/2006/February/sample.jpg',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }, {
                'name': 'photos/2006/March/sample.jpg',
                'last_modified':
                '2014-05-07T19:47:54.592270',
                'hash': 'Y',
                'bytes': 1,
            }
        ]
        for obj in old_versions:
            self.app.register('GET', '/v1/AUTH_test/bucket+versions?'
                              'format=json&prefix=%s/' % obj,
                              swob.HTTPOk, {}, json.dumps(old_versions[obj]))
        self.app.register('GET', '/v1/AUTH_test/bucket?format=json',
                          swob.HTTPOk,
                          {'x-container-sysmeta-swift3-acl': '["test:tester"]',
                           'x-container-sysmeta-swift3-versioning':
                               '"Enabled"'},
                          json.dumps(latest_versions))
        self.app.register('GET', '/v1/AUTH_test/bucket?format=json&prefix=X',
                          swob.HTTPOk,
                          {'x-container-sysmeta-swift3-acl': '["test:tester"]',
                           'x-container-sysmeta-swift3-versioning':
                               '"Enabled"'},
                          '[]')
        self.app.register('GET', '/v1/AUTH_test/bucket?format=json&'
                          'prefix=photos/2006/',
                          swob.HTTPOk,
                          {'x-container-sysmeta-swift3-acl': '["test:tester"]',
                           'x-container-sysmeta-swift3-versioning':
                               '"Enabled"'},
                          json.dumps(latest_versions_photos_2006))
        self.app.register('GET', '/v1/AUTH_test/bucket?format=json&prefix=obj',
                          swob.HTTPOk,
                          {'x-container-sysmeta-swift3-acl': '["test:tester"]',
                           'x-container-sysmeta-swift3-versioning':
                               '"Enabled"'},
                          json.dumps(latest_versions_obj))
        self.app.register('GET', '/v1/AUTH_test/bucket?format=json&marker=',
                          swob.HTTPOk,
                          {'x-container-sysmeta-swift3-acl': '["test:tester"]',
                           'x-container-sysmeta-swift3-versioning':
                               '"Enabled"'},
                          json.dumps(latest_versions))
        self.app.register('GET', '/v1/AUTH_test/bucket?format=json&marker=X',
                          swob.HTTPOk,
                          {'x-container-sysmeta-swift3-acl': '["test:tester"]',
                           'x-container-sysmeta-swift3-versioning':
                               '"Enabled"'},
                          '[]')

        self.app.register('HEAD', '/v1/AUTH_test/bucket/obj1',
                          swob.HTTPOk,
                          {'x-timestamp': 3,
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions/004obj1/'
                          '0000000001.00000',
                          swob.HTTPOk,
                          {'x-timestamp': '0000000001.00000',
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions/004obj1/'
                          '0000000002.00000',
                          swob.HTTPOk,
                          {'x-timestamp': '0000000002.00000',
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket/obj2',
                          swob.HTTPOk,
                          {'x-timestamp': 3,
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions/004obj2/'
                          '0000000001.00000',
                          swob.HTTPOk,
                          {'x-timestamp': '0000000001.00000',
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions/004obj2/'
                          '0000000002.00000',
                          swob.HTTPOk,
                          {'x-timestamp': '0000000002.00000',
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket/obj3',
                          swob.HTTPOk,
                          {'x-timestamp': 3,
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket/'
                          'photos/2006/January/sample.jpg',
                          swob.HTTPOk,
                          {'x-timestamp': 3,
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions/'
                          '01ephotos/2006/January/sample.jpg/'
                          '0000000001.00000',
                          swob.HTTPOk,
                          {'x-timestamp': '0000000001.00000',
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket/'
                          'photos/2006/February/sample.jpg',
                          swob.HTTPOk,
                          {'x-timestamp': 3,
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions/'
                          '01fphotos/2006/February/sample.jpg/'
                          '0000000001.00000',
                          swob.HTTPOk,
                          {'x-timestamp': '0000000001.00000',
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket/'
                          'photos/2006/March/sample.jpg',
                          swob.HTTPOk,
                          {'x-timestamp': 3,
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions/'
                          '01cphotos/2006/March/sample.jpg/'
                          '0000000001.00000',
                          swob.HTTPOk,
                          {'x-timestamp': '0000000001.00000',
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/bucket/'
                          'videos/2006/March/sample.wmv',
                          swob.HTTPOk,
                          {'x-timestamp': 3,
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions/'
                          '01cvideos/2006/March/sample.wmv/'
                          '0000000001.00000',
                          swob.HTTPOk,
                          {'x-timestamp': '0000000001.00000',
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket/sample.jpg',
                          swob.HTTPOk,
                          {'x-timestamp': 3,
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket+versions/'
                          '00asample.jpg/'
                          '0000000001.00000',
                          swob.HTTPOk,
                          {'x-timestamp': '0000000001.00000',
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)

        self.app.register('GET', '/v1/AUTH_test/noversions+versions?'
                          'format=json',
                          swob.HTTPNotFound, {}, None)
        self.app.register('HEAD', '/v1/AUTH_test/noversions',
                          swob.HTTPNoContent,
                          {'x-container-sysmeta-swift3-acl':
                           '["test:tester"]'},
                          None)
        self.app.register('GET', '/v1/AUTH_test/noversions?format=json',
                          swob.HTTPNoContent,
                          {'x-container-sysmeta-swift3-acl':
                           '["test:tester"]'},
                          '[]')

    def test_bucket_object_versions_GET_error(self):
        req = Request.blank('/noversions?versions',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListVersionsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_object_versions_GET(self):
        req = Request.blank('/bucket?versions',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListVersionsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_object_versions_GET_encoding_type(self):
        req = Request.blank('/bucket?versions&encoding-type=url',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListVersionsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_object_versions_GET_encoding_type_error(self):
        req = Request.blank('/bucket?versions&encoding-type=xml',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_object_versions_GET_max_keys(self):
        req = Request.blank('/bucket?versions&max-keys=1',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListVersionsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_object_versions_GET_negative_max_keys(self):
        req = Request.blank('/bucket?versions&max-keys=-1',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_object_versions_GET_str_max_keys(self):
        req = Request.blank('/bucket?versions&max-keys=a',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_object_versions_GET_prefix(self):
        req = Request.blank('/bucket?versions&prefix=X',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListVersionsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_object_versions_GET_prefix_delimiter(self):
        req = Request.blank('/bucket?versions&prefix=obj&delimiter=3',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListVersionsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_object_versions_GET_key_marker(self):
        req = Request.blank('/bucket?versions&key-marker=X',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListVersionsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_object_versions_GET_version_id_marker(self):
        req = Request.blank('/bucket?versions&key-marker=X&'
                            'version-id-marker=Y',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListVersionsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_object_versions_GET_common_prefix(self):
        req = Request.blank('/bucket?versions&prefix=photos/2006/&delimiter=/',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        fromstring(body, 'ListVersionsResult')
        self.assertEquals(status.split()[0], '200')

    def test_bucket_object_versions_GET_object_name(self):
        req = Request.blank('/bucket/obj?versions',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '400')

    def test_bucket_versioning_PUT_no_status(self):
        req = Request.blank('/bucket?versioning',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=error_versioning_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body),
                          'IllegalVersioningConfigurationException')

    def _test_bucket_versioning_PUT(self, status, bucket='bucket'):
        version_xml = versioning_xml_fmt % status
        req = Request.blank('/%s?versioning' % bucket,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=version_xml)
        return self.call_swift3(req)

    def test_bucket_versioning_PUT_invalid_xml(self):
        status, headers, body = self._test_bucket_versioning_PUT('Invalid')
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_versioning_PUT_invalid_string(self):
        req = Request.blank('/bucket?versioning',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='invalid')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_versioning_PUT_to_lifecycled_bucket(self):
        status, headers, body = self._test_bucket_versioning_PUT('Enabled',
                                                                 'lifecycled')
        self.assertEquals(self._get_error_code(body), 'InvalidBucketState')

    def test_bucket_versioning_PUT_enabled(self):
        status, headers, body = self._test_bucket_versioning_PUT('Enabled')
        self.assertEquals(status.split()[0], '200')
        headers = [h for m, p, h in self.app.calls_with_headers
                   if m == 'POST'][-1]
        status_key_name = 'x-container-sysmeta-swift3-Versioning'
        self.assertEquals(headers[status_key_name], '"Enabled"')
        self.assertEquals(headers['X-Versions-Location'], 'bucket+versions')

    def test_bucket_versioning_PUT_suspended(self):
        status, headers, body = self._test_bucket_versioning_PUT('Suspended')
        self.assertEquals(status.split()[0], '200')
        headers = [h for m, p, h in self.app.calls_with_headers
                   if m == 'POST'][-1]
        status_key_name = 'x-container-sysmeta-swift3-Versioning'
        self.assertEquals(headers[status_key_name], '"Suspended"')
        self.assertEquals(headers['X-Versions-Location'], 'bucket+versions')

    def test_object_versioning_PUT(self):
        version_xml = versioning_xml_fmt % 'Enabled'
        req = Request.blank('/bucket/object?versioning',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=version_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def _test_bucket_versioning_GET(self, header):
        bucket_name = 'junk'
        header.update(
            {'x-container-sysmeta-swift3-acl': '["test:tester"]',
             'x-timestamp': '0'})
        self.app.register('HEAD', '/v1/AUTH_test/%s' % bucket_name,
                          swob.HTTPNoContent, header, None)
        req = Request.blank('/%s?versioning' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        return self.call_swift3(req)

    def test_bucket_versioning_GET_invalid(self):
        header = {'x-container-sysmeta-swift3-Versioning': '"Invalid"'}
        status, headers, body = self._test_bucket_versioning_GET(header)
        self.assertEquals(status.split()[0], '500')

    def test_bucket_versioning_GET_enabled(self):
        header = {'x-container-sysmeta-swift3-Versioning': '"Enabled"'}
        status, headers, body = self._test_bucket_versioning_GET(header)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'VersioningConfiguration')
        self.assertEquals(elem.tag, 'VersioningConfiguration')
        self.assertEquals(elem.find('./Status').text, 'Enabled')

    def test_bucket_versioning_GET_suspended(self):
        header = {'x-container-sysmeta-swift3-Versioning': '"Suspended"'}
        status, headers, body = self._test_bucket_versioning_GET(header)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'VersioningConfiguration')
        self.assertEquals(elem.tag, 'VersioningConfiguration')
        self.assertEquals(elem.find('./Status').text, 'Suspended')

    def test_bucket_versioning_GET_disabled(self):
        status, headers, body = self._test_bucket_versioning_GET({})
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'VersioningConfiguration')
        self.assertEquals(elem.tag, 'VersioningConfiguration')
        self.assertEquals(elem.text, None)

    def test_object_GET_delete_marker(self):
        req = Request.blank('/bucket/delete-marker',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NoSuchKey')
        self.assertEquals(headers['x-amz-delete-marker'], 'true')

    def test_object_HEAD_delete_marker(self):
        req = Request.blank('/bucket/delete-marker',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '404')
        self.assertEquals(headers['x-amz-delete-marker'], 'true')

    def test_object_DELETE_delete_marker(self):
        req = Request.blank('/bucket/delete-marker',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')
        self.assertEquals(headers['x-amz-delete-marker'], 'true')

    def test_bucket_versioning_owner_error(self):
        bucket_name = 'bucket'
        req = Request.blank('/%s?versioning' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:user:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')
