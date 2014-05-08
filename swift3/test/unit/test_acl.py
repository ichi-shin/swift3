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
from mock import patch

from swift.common import swob
from swift.common.swob import Request

from swift3.acl import ACL, ACLPublicReadWrite, LogDelivery
from swift3.etree import Element, SubElement, tostring, fromstring
from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.response import MalformedACLError
from swift3.request import VersionId

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'

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

acl_template_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<AccessControlPolicy ' \
    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
    '<Owner>' \
    '<ID>%s</ID>' \
    '<DisplayName>%s</DisplayName>' \
    '</Owner>' \
    '<AccessControlList>' \
    '<Grant>' \
    '<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
    'xsi:type="CanonicalUser">' \
    '<ID>test:tester</ID>' \
    '<DisplayName>test:tester</DisplayName>' \
    '</Grantee>' \
    '<Permission>%s</Permission>' \
    '</Grant>' \
    '</AccessControlList>' \
    '</AccessControlPolicy>'

acl_group_template_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<AccessControlPolicy ' \
    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
    '<Owner>' \
    '<ID>test:other</ID>' \
    '<DisplayName>test:other</DisplayName>' \
    '</Owner>' \
    '<AccessControlList>' \
    '<Grant>' \
    '<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
    'xsi:type="Group">' \
    '<URI>%s</URI>' \
    '</Grantee>' \
    '<Permission>READ</Permission>' \
    '</Grant>' \
    '</AccessControlList>' \
    '</AccessControlPolicy>'

acl_email_template_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<AccessControlPolicy ' \
    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
    '<Owner>' \
    '<ID>test:other</ID>' \
    '<DisplayName>test:other</DisplayName>' \
    '</Owner>' \
    '<AccessControlList>' \
    '<Grant>' \
    '<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
    'xsi:type="AmazonCustomerByEmail">' \
    '<EmailAddress>Grantees@email.com</EmailAddress>' \
    '</Grantee>' \
    '<Permission>READ</Permission>' \
    '</Grant>' \
    '</AccessControlList>' \
    '</AccessControlPolicy>'

acl_invalid_group_template_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<AccessControlPolicy ' \
    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
    '<Owner>' \
    '<ID>test:other</ID>' \
    '<DisplayName>test:other</DisplayName>' \
    '</Owner>' \
    '<AccessControlList>' \
    '<Grant>' \
    '<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
    'xsi:type="Invalid">' \
    '<EmailAddress>Grantees@email.com</EmailAddress>' \
    '</Grantee>' \
    '<Permission>READ</Permission>' \
    '</Grant>' \
    '</AccessControlList>' \
    '</AccessControlPolicy>'

noacl_template_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<AccessControlPolicy ' \
    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
    '<Owner>' \
    '<ID>%s</ID>' \
    '<DisplayName>%s</DisplayName>' \
    '</Owner>' \
    '<AccessControlList/>' \
    '</AccessControlPolicy>'


class TestSwift3Acl(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Acl, self).setUp()

        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'AUTH_test/bucket/0/0',
                                       'last_modified': 'X',
                                       'hash': 'Y',
                                       'bytes': 'Z'}]))
        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules/AUTH_test/bucket/0/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD', '/v1/AUTH_test/junk', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'test:tester'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket/object',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': 'test:tester'},
                          None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/junk/0',
                          swob.HTTPOk, {}, acl_xml)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/bucket/0/object/0',
                          swob.HTTPOk, {}, acl_xml)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/bucket/0',
                          swob.HTTPOk, {},
                          ACLPublicReadWrite().to_xml('test:other',
                                                      'test:other'))
        self.app.register('POST',
                          '/v1/AUTH_test/bucket',
                          swob.HTTPNoContent, {}, None)
        self.app.register('PUT',
                          '/v1/AUTH_test/bucket',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/AUTH_test/bucket/object',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/junk/0',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/bucket/0/object/0',
                          swob.HTTPCreated, {}, None)

        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/bucket/0',
                          swob.HTTPCreated, {}, None)

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

    def _check_acl(self, owner, body):
        elem = fromstring(body, 'AccessControlPolicy')
        self.assertEquals(elem.tag, 'AccessControlPolicy')
        permission = elem.find('./AccessControlList/Grant/Permission').text
        self.assertEquals(permission, 'FULL_CONTROL')
        name = elem.find('./AccessControlList/Grant/Grantee/ID').text
        self.assertEquals(name, owner)

    def test_bucket_acl_GET(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?acl' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        self._check_acl('test:tester', body)

    def test_bucket_acl_PUT(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?acl' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_acl_PUT_with_other_owner(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?acl' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=other_acl_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_acl_GET(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        self._check_acl('test:tester', body)

    def test_object_acl_PUT_xml_error(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body="invalid xml")
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedACLError')

    def test_object_acl_PUT_xml(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_private(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'private'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_public_read(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'public-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_public_read_write(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'public-read-write'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_authenticated_read(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'authenticated-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_bucket_owner_read(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'bucket-owner-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_bucket_owner_full_control(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'bucket-owner-full-control'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_canned_acl_log_delivery_write(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'log-delivery-write'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_invalid_canned_acl(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-acl': 'invalid'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_grant_read(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read': 'id=test:tester'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_grant_write(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-write': 'id=test:tester'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_grant_read_acp(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read-acp': 'id=test:tester'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_grant_write_acp(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-write-acp':
                                     'id=test:tester'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_grant_full_control(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-full-control':
                                     'id=test:tester'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_grant_with_both_header_and_xml(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-full-control':
                                     'id=test:tester'},
                            body=acl_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'UnexpectedContent')

    def test_grant_with_both_header_and_canned_acl(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-full-control':
                                     'id=test:tester',
                                     'x-amz-acl': 'public-read'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidRequest')

    def test_grant_invalid_permission(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-invalid': 'id=test:tester'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedACLError')

    def test_grant_email(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read': 'emailAddress=a@b.c'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NotImplemented')

    def test_grant_email_xml(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_email_template_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NotImplemented')

    def test_grant_invalid_group_xml(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_invalid_group_template_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedACLError')

    def test_grant_authenticated_users(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read':
                                     'uri="http://acs.amazonaws.com/groups/'
                                     'global/AuthenticatedUsers"'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_grant_all_users(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read':
                                     'uri="http://acs.amazonaws.com/groups/'
                                     'global/AllUsers"'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_grant_log_delivery(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read':
                                     'uri="http://acs.amazonaws.com/groups/'
                                     's3/LogDelivery"'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_grant_invalid_uri(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read':
                                     'uri="http://localhost/"'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_grant_invalid_uri_xml(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_group_template_xml % 'invalid')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_grant_invalid_target(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'x-amz-grant-read': 'key=value'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_GET_without_permission(self):
        owner = 'test:other'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_GET_with_read_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'READ')

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_with_fullcontrol_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'FULL_CONTROL')

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_with_owner_permission(self):
        owner = 'test:tester'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_bucket_DELETE_without_permission(self):
        owner = 'test:other'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('DELETE', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_DELETE_with_write_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'WRITE')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('DELETE', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '403')

    def test_bucket_DELETE_with_fullcontrol_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'FULL_CONTROL')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('DELETE', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '403')

    def test_bucket_DELETE_with_owner_permission(self):
        owner = 'test:tester'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('DELETE', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '204')

    def test_bucket_GET_acl_without_permission(self):
        owner = 'test:other'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_GET_acl_with_read_acp_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'READ_ACP')

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_acl_with_fullcontrol_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'FULL_CONTROL')

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_acl_with_owner_permission(self):
        owner = 'test:tester'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_bucket_PUT_acl_without_permission(self):
        owner = 'test:other'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_xml)
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_bucket_PUT_acl_with_write_acp_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'WRITE_ACP')

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPCreated, {}, None)
        req = Request.blank('/acltest?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_xml)
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_bucket_PUT_acl_with_fullcontrol_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'FULL_CONTROL')

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPCreated, {}, None)
        req = Request.blank('/acltest?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_xml)
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_bucket_PUT_acl_with_owner_permission(self):
        owner = 'test:tester'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPCreated, {}, None)
        req = Request.blank('/acltest?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_xml)
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_without_permission(self):
        owner = 'test:other'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('GET', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, '')
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_GET_with_read_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'READ')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('GET', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, '')
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_with_fullcontrol_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'FULL_CONTROL')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('GET', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, '')
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_with_owner_permission(self):
        owner = 'test:tester'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('GET', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, '')
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_without_permission(self):
        owner = 'test:other'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0}, None)
        self.app.register('PUT', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPCreated, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPNotFound, {}, None)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_PUT_with_write_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % ('test:tester', 'test:tester', 'WRITE')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Read': owner,
                           'X-Container-Write': owner}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0}, None)
        self.app.register('PUT', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPCreated, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPNotFound, {}, None)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_with_fullcontrol_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % ('test:tester', 'test:tester', 'FULL_CONTROL')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Read': owner,
                           'X-Container-Write': owner}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0}, None)
        self.app.register('PUT', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPCreated, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPNotFound, {}, None)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_with_owner_permission(self):
        owner = 'test:tester'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Read': owner,
                           'X-Container-Write': owner}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0}, None)
        self.app.register('PUT', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPCreated, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPNotFound, {}, None)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_DELETE_without_permission(self):
        owner = 'test:other'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0}, None)
        self.app.register('DELETE', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPNoContent, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPNotFound, {}, None)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_DELETE_with_write_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'WRITE')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0}, None)
        self.app.register('DELETE', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPNoContent, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPNotFound, {}, None)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_object_DELETE_with_fullcontrol_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'FULL_CONTROL')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0}, None)
        self.app.register('DELETE', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPNoContent, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPNotFound, {}, None)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_object_DELETE_with_owner_permission(self):
        owner = 'test:tester'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0}, None)
        self.app.register('DELETE', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPNoContent, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPNotFound, {}, None)
        req = Request.blank('/acltest/acltest',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_object_GET_acl_without_permission(self):
        owner = 'test:other'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest/acltest?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_GET_acl_with_read_acp_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'READ_ACP')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest/acltest?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_acl_with_fullcontrol_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'FULL_CONTROL')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest/acltest?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_acl_with_owner_permission(self):
        owner = 'test:tester'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest/acltest?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_GET_acl_with_version_id(self):
        version_id = VersionId(1)
        owner = 'test:tester'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)

        self.app.register('HEAD', '/v1/AUTH_test/acltest+versions',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD',
                          '/v1/AUTH_test/acltest+versions/'
                          '006acltest/0000000001.00000',
                          swob.HTTPOk, self.response_headers, self.object_body)
        self.app.register('GET', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk, self.response_headers, self.object_body)
        self.app.register('GET', '/v1/AUTH_test/acltest+versions?format=json',
                          swob.HTTPOk,
                          {'x-container-meta-[swift3]-timestamp': 0},
                          json.dumps([{'name': '006acltest/0000000001.00000',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'}]))

        req = Request.blank('/acltest/acltest?acl&versionId=' + str(version_id),
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_acl_without_permission(self):
        owner = 'test:other'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPCreated, {}, None)
        req = Request.blank('/acltest/acltest?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_object_PUT_acl_with_write_acp_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'WRITE_ACP')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPCreated, {}, None)
        req = Request.blank('/acltest/acltest?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_acl_with_fullcontrol_permission(self):
        owner = 'test:other'
        acl = acl_template_xml % (owner, owner, 'FULL_CONTROL')

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPCreated, {}, None)
        req = Request.blank('/acltest/acltest?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_acl_with_owner_permission(self):
        owner = 'test:tester'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPCreated, {}, None)
        req = Request.blank('/acltest/acltest?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_PUT_acl_with_version_id(self):
        version_id = VersionId(1)
        owner = 'test:tester'
        acl = noacl_template_xml % (owner, owner)

        self.app.register('HEAD', '/v1/AUTH_test/acltest',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('HEAD', '/v1/AUTH_test/acltest/acltest',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': owner}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPOk, {}, acl)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/acltest/0/acltest/0',
                          swob.HTTPCreated, {}, None)

        self.app.register('HEAD', '/v1/AUTH_test/acltest+versions',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('GET',
                          '/v1/AUTH_test/acltest+versions?format=json',
                          swob.HTTPOk,
                          {'x-container-meta-[swift3]-timestamp': 0},
                          json.dumps([{'name': '006acltest/0000000001.00000',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'}]))
        self.app.register('HEAD',
                          '/v1/AUTH_test/acltest+versions/'
                          '006acltest/0000000001.00000',
                          swob.HTTPOk, self.response_headers, self.object_body)

        req = Request.blank('/acltest/acltest?acl&versionId=' + str(version_id),
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=acl_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_authenticated_users(self):
        owner = 'test:other'
        acl = acl_group_template_xml % \
            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_all_users(self):
        owner = 'test:other'
        acl = acl_group_template_xml % \
            'http://acs.amazonaws.com/groups/global/AllUsers'

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_bucket_GET_log_delivery(self):
        owner = 'test:other'
        acl = acl_group_template_xml % \
            'http://acs.amazonaws.com/groups/s3/LogDelivery'

        self.app.register('GET', '/v1/AUTH_test/acltest', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': owner},
                          json.dumps([]))
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/acltest/0',
                          swob.HTTPOk, {}, acl)
        req = Request.blank('/acltest',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization':
                                     'AWS test:.log_delivery:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_too_many_grants(self):
        def add_grant(parent, user_id):
            grant_elem = SubElement(parent, 'Grant')
            grantee_elem = SubElement(grant_elem, 'Grantee',
                                      nsmap={'xsi': XMLNS_XSI})
            grantee_elem.set('{%s}type' % XMLNS_XSI, 'CanonicalUser')
            SubElement(grantee_elem, 'ID').text = user_id
            SubElement(grantee_elem, 'DisplayName').text = user_id
            SubElement(grant_elem, 'Permission').text = 'READ'

        acp_elem = Element('AccessControlPolicy')

        owner_elem = SubElement(acp_elem, 'Owner')
        SubElement(owner_elem, 'ID').text = 'owner'
        SubElement(owner_elem, 'DisplayName').text = 'owner'

        acl_elem = SubElement(acp_elem, 'AccessControlList')
        for n in range(100):
            user_id = 'user%d' % n
            add_grant(acl_elem, user_id)

        xml = tostring(acp_elem)
        ACL(xml=xml)

        add_grant(acl_elem, 'user101')
        xml = tostring(acp_elem)
        self.assertRaises(MalformedACLError, ACL, xml=xml)

    @patch('swift3.utils.ALLOW_CONTAINER_PUBLIC_WRITE', False)
    def test_object_acl_PUT_without_public_write_permission(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization':
                                     'AWS test:tester:hmac',
                                     'x-amz-acl': 'public-read-write'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    @patch('swift3.utils.ALLOW_CONTAINER_PUBLIC_WRITE', False)
    def test_object_PUT_acl_without_public_write_permission(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization':
                                     'AWS test:tester:hmac',
                                     'x-amz-acl': 'public-read-write'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    @patch('swift3.utils.ALLOW_CONTAINER_PUBLIC_WRITE', False)
    def test_bucket_acl_PUT_without_public_write_permission(self):
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization':
                                     'AWS test:tester:hmac',
                                     'x-amz-acl': 'public-read-write'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    @patch('swift3.utils.ALLOW_CONTAINER_PUBLIC_WRITE', False)
    def test_bucket_PUT_acl_without_public_write_permission(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?acl' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization':
                                     'AWS test:tester:hmac',
                                     'x-amz-acl': 'public-read-write'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    @patch('swift3.utils.ALLOW_CONTAINER_PUBLIC_WRITE', False)
    def test_forbid_public_write(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization':
                                     'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_log_delivery_user(self):
        grant = LogDelivery()
        self.assertTrue('test:.log_delivery' in grant)
        self.assertTrue('test:log_delivery' not in grant)
        self.assertTrue('.log_delivery' in grant)
        self.assertTrue('log_delivery' not in grant)
