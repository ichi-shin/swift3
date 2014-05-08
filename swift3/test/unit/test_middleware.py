# Copyright (c) 2011-2014 OpenStack Foundation.
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

import unittest
from datetime import datetime
import hashlib
import base64
from urllib import unquote, quote
import simplejson as json
import time
from mock import patch

from swift.common import swob
from swift.common.swob import Request

from swift3 import middleware as swift3
from swift3 import utils
from swift3.test.unit.helpers import FakeSwift
from swift3.etree import fromstring


def fake_start_response(*args, **kwargs):
    pass


def md5hex(s):
    return hashlib.md5(s).hexdigest()


class Swift3TestCase(unittest.TestCase):
    def __init__(self, name):
        unittest.TestCase.__init__(self, name)
        self.conf = {
            'log_level': 'debug',
            'pretty_print_xml': True,
            'storage_domain': 'localhost',
        }

    def setUp(self):
        self.app = FakeSwift()
        self.swift3 = swift3.filter_factory(self.conf)(self.app)

        # container '.' will be accessed to resolve a tenant name
        self.app.register('HEAD', '/v1/AUTH_test/.', swob.HTTPNotFound,
                          {}, None)
        self.app.register('HEAD', '/v1/AUTH_X/.', swob.HTTPNotFound,
                          {}, None)
        self.app.register('PUT', '/v1/.swift3/acl',
                          swob.HTTPAccepted, {}, None)
        self.app.register('PUT', '/v1/.swift3/lifecycle_rules',
                          swob.HTTPAccepted, {}, None)

    def _get_error_code(self, body):
        elem = fromstring(body, 'Error')
        self.assertEquals(elem.tag, 'Error')
        return elem.find('./Code').text

    def _test_method_error(self, method, path, response_class, headers=None,
                           body=None):
        if headers is None:
            headers = {}
        headers.update({'x-container-meta-[swift3]-timestamp': 0,
                        'X-Container-Meta-[Swift3]-Owner': 'test:tester',
                        'X-Object-Meta-[Swift3]-Owner': 'test:tester'})
        uri = '/v1/AUTH_test' + path
        if uri == '/v1/AUTH_test/':
            uri = '/v1/AUTH_test'
        self.app.register(method, uri, response_class,
                          headers, body)
        headers.update({'Authorization': 'AWS test:tester:hmac'})
        req = Request.blank(path, environ={'REQUEST_METHOD': method},
                            headers=headers)
        status, headers, body = self.call_swift3(req)
        #print body
        if body == '':
            return status
        return self._get_error_code(body)

    def call_app(self, req, app=None, expect_exception=False):
        if app is None:
            app = self.app

        req.headers.setdefault("User-Agent", "Mozzarella Foxfire")

        status = [None]
        headers = [None]

        def start_response(s, h, ei=None):
            status[0] = s
            headers[0] = swob.HeaderKeyDict(h)

        body_iter = app(req.environ, start_response)
        body = ''
        caught_exc = None
        try:
            for chunk in body_iter:
                body += chunk
        except Exception as exc:
            if expect_exception:
                caught_exc = exc
            else:
                raise

        if expect_exception:
            return status[0], headers[0], body, caught_exc
        else:
            return status[0], headers[0], body

    def call_swift3(self, req, **kwargs):
        return self.call_app(req, app=self.swift3, **kwargs)


class TestSwift3Middleware(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Middleware, self).setUp()

        self.app.register('GET', '/something', swob.HTTPOk, {}, 'FAKE APP')
        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'AUTH_X/bucket/0/0',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'}]))
        self.app.register('GET',
                          '/v1/.swift3/lifecycle_rules/AUTH_X/bucket/0/0',
                          swob.HTTPOk, {}, None)

        private_acl = '<?xml version="1.0" encoding="UTF-8"?>' \
            '<AccessControlPolicy ' \
            'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
            '<Owner>' \
            '<ID>X:Y</ID><DisplayName>X:Y</DisplayName>' \
            '</Owner>' \
            '<AccessControlList/>' \
            '</AccessControlPolicy>'

        self.app.register('GET',
                          '/v1/.swift3/upload_in_progress/AUTH_X/bucket/0/'
                          'object/123456789abcdef',
                          swob.HTTPOk, {}, private_acl)
        self.app.register('PUT',
                          '/v1/AUTH_X/bucket+segments/object/'
                          '123456789abcdef/1',
                          swob.HTTPCreated, {}, None)

        self.app.register('GET', '/v1/.swift3/acl/AUTH_X/bucket/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET', '/v1/.swift3/acl/AUTH_X/bucket/0/object/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('PUT', '/v1/.swift3/acl/AUTH_X/bucket/0/object/0',
                          swob.HTTPOk, {}, None)
        self.app.register('GET', '/v1/.swift3/acl/AUTH_test/bucket/0/'
                          'object:1/0',
                          swob.HTTPNotFound, {}, None)

        self.app.register('HEAD', '/v1/AUTH_X/bucket', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Meta-[Swift3]-Owner': 'X:Y'}, None)
        self.app.register('GET', '/v1/AUTH_X/bucket', swob.HTTPOk,
                          {'x-container-meta-[swift3]-timestamp': 0}, '[]')
        self.app.register('GET', '/v1/AUTH_X/bucket/object', swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': 'X:Y'},
                          'FAKE APP')
        self.app.register('PUT', '/v1/AUTH_X/bucket/object', swob.HTTPCreated,
                          {}, None)

        self.app.register('HEAD', '/v1/AUTH_test/.', swob.HTTPNotFound,
                          {}, None)
        self.app.register('HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0}, None)
        self.app.register('GET', '/v1/AUTH_test/bucket/object:1',
                          swob.HTTPOk,
                          {'x-object-meta-[swift3]-timestamp': 0,
                           'X-Object-Meta-[Swift3]-Owner': 'test:tester'},
                          'FAKE APP')

    def test_non_s3_request_passthrough(self):
        req = Request.blank('/something')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(body, 'FAKE APP')

    def test_bad_format_authorization(self):
        req = Request.blank('/something',
                            headers={'Authorization': 'hoge'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_no_aws_authorization(self):
        req = Request.blank('/something',
                            headers={'Authorization': 'S3 test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_invalid_authorization_info(self):
        req = Request.blank('/something',
                            headers={'Authorization': 'AWS invalid'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bad_method(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MethodNotAllowed')

    def test_path_info_encode(self):
        bucket_name = 'b%75cket'
        object_name = 'ob%6aect:1'
        req = Request.blank('/%s/%s' % (bucket_name, object_name),
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        path_info = req.environ['PATH_INFO']
        self.assertEquals(req.path, quote(path_info))
        self.assertEquals(path_info, unquote(path_info))

    def test_canonical_string(self):
        """
        test_canonical_string
        The hashes here were generated by running the same requests against
        boto.utils.canonical_string
        """
        def canonical_string(path, headers):
            if '?' in path:
                path, query_string = path.split('?', 1)
            else:
                query_string = ''

            req = swift3.S3Request({
                'REQUEST_METHOD': 'GET',
                'PATH_INFO': path,
                'QUERY_STRING': query_string,
                'HTTP_AUTHORIZATION': 'AWS X:Y:Z',
            })
            req.headers.update(headers)
            return req._canonical_string()

        def verify(hash, path, headers):
            str = canonical_string(path, headers)
            self.assertEquals(hash, hashlib.md5(str).hexdigest())

        verify('6dd08c75e42190a1ce9468d1fd2eb787', '/bucket/object',
               {'Content-Type': 'text/plain', 'X-Amz-Something': 'test',
                'Date': 'whatever'})

        verify('c8447135da232ae7517328f3429df481', '/bucket/object',
               {'Content-Type': 'text/plain', 'X-Amz-Something': 'test'})

        verify('bf49304103a4de5c325dce6384f2a4a2', '/bucket/object',
               {'content-type': 'text/plain'})

        verify('be01bd15d8d47f9fe5e2d9248cc6f180', '/bucket/object', {})

        verify('e9ec7dca45eef3e2c7276af23135e896', '/bucket/object',
               {'Content-MD5': 'somestuff'})

        verify('a822deb31213ad09af37b5a7fe59e55e', '/bucket/object?acl', {})

        verify('cce5dd1016595cb706c93f28d3eaa18f', '/bucket/object',
               {'Content-Type': 'text/plain', 'X-Amz-A': 'test',
                'X-Amz-Z': 'whatever', 'X-Amz-B': 'lalala',
                'X-Amz-Y': 'lalalalalalala'})

        verify('7506d97002c7d2de922cc0ec34af8846', '/bucket/object',
               {'Content-Type': None, 'X-Amz-Something': 'test'})

        verify('28f76d6162444a193b612cd6cb20e0be', '/bucket/object',
               {'Content-Type': None,
                'X-Amz-Date': 'Mon, 11 Jul 2011 10:52:57 +0000',
                'Date': 'Tue, 12 Jul 2011 10:52:57 +0000'})

        verify('ed6971e3eca5af4ee361f05d7c272e49', '/bucket/object',
               {'Content-Type': None,
                'Date': 'Tue, 12 Jul 2011 10:52:57 +0000'})

        str1 = canonical_string('/', headers=
                                {'Content-Type': None,
                                 'X-Amz-Something': 'test'})
        str2 = canonical_string('/', headers=
                                {'Content-Type': '',
                                 'X-Amz-Something': 'test'})
        str3 = canonical_string('/', headers={'X-Amz-Something': 'test'})

        self.assertEquals(str1, str2)
        self.assertEquals(str2, str3)

    def test_signed_urls_expired(self):
        expire = '1000000000'
        req = Request.blank('/bucket/object?Signature=X&Expires=%s&'
                            'AWSAccessKeyId=Z' % expire,
                            environ={'REQUEST_METHOD': 'GET'})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_signed_urls(self):
        expire = '10000000000'
        req = Request.blank('/bucket/object?Signature=Z&Expires=%s&'
                            'AWSAccessKeyId=X:Y' % expire,
                            environ={'REQUEST_METHOD': 'GET'})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(status.split()[0], '200')
        for _, _, headers in self.app.calls_with_headers:
            self.assertEquals(headers['Authorization'], 'AWS X:Y:Z')
            self.assertEquals(headers['Date'], expire)

    def test_signed_urls_invalid_expire(self):
        expire = 'invalid'
        req = Request.blank('/bucket/object?Signature=Z&Expires=%s&'
                            'AWSAccessKeyId=X:Y' % expire,
                            environ={'REQUEST_METHOD': 'GET'})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_signed_urls_no_sign(self):
        expire = 'invalid'
        req = Request.blank('/bucket/object?Expires=%s&'
                            'AWSAccessKeyId=X:Y' % expire,
                            environ={'REQUEST_METHOD': 'GET'})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_date_header(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        req.headers['Date'] = time.strftime(
            "%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_invalid_date_header(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y'})
        req.headers['Date'] = 'invalid'
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_too_old_date_header(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y'})
        req.headers['Date'] = 'Wed, 08 Mar 1006 00:00:00 GMT'
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_request_time_too_skewed(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y'})
        req.headers['Date'] = 'Wed, 08 Mar 2006 00:00:00 GMT'
        req.content_type = 'text/plain'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'RequestTimeTooSkewed')

    def test_bucket_virtual_hosted_style(self):
        req = Request.blank('/',
                            environ={'HTTP_HOST': 'bucket.localhost:80',
                                     'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_virtual_hosted_style(self):
        req = Request.blank('/object',
                            environ={'HTTP_HOST': 'bucket.localhost:80',
                                     'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_token_generation(self):
        req = Request.blank('/bucket/object?uploadId=123456789abcdef'
                            '&partNumber=1',
                            environ={'REQUEST_METHOD': 'PUT'})
        req.headers['Authorization'] = 'AWS X:Y:Z'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        _, _, headers = self.app.calls_with_headers[-1]
        self.assertEquals(base64.urlsafe_b64decode(headers['X-Auth-Token']),
                          'PUT\n\n\n/bucket/object'
                          '?partNumber=1&uploadId=123456789abcdef')

    def test_keystone_auth(self):
        app = FakeSwift(auth='keystone')
        app.register('HEAD', '/v1/AUTH_X/.', swob.HTTPNotFound,
                     {'X-Timestamp': 0}, None)
        app.register('HEAD', '/v1/AUTH_X/bucket', swob.HTTPNoContent,
                     {'X-Timestamp': 0}, None)
        app.register('PUT', '/v1/AUTH_X/bucket', swob.HTTPCreated,
                     {'X-Timestamp': 0}, None)
        app.register('POST', '/v1/AUTH_X/bucket', swob.HTTPNoContent,
                     {'X-Timestamp': 0}, None)
        app.register('PUT', '/v1/.swift3/acl',
                     swob.HTTPAccepted, {}, None)
        app.register('PUT', '/v1/.swift3/acl/AUTH_X/bucket/0',
                     swob.HTTPCreated, {}, None)
        req = Request.blank('/bucket',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS X:Y:Z'})
        s3_app = swift3.filter_factory(self.conf)(app)
        status, headers, body = self.call_app(req, app=s3_app)
        print body
        self.assertEquals(status.split()[0], '200')

    def test_update_swift3_conf(self):
        self.assertEquals(utils.LOCATION, 'US')
        utils.update_swift3_conf({'location': 'EU'})
        self.assertEquals(utils.LOCATION, 'EU')

    def test_invalid_uri(self):
        req = Request.blank('/bucket/invalid\xffname',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidURI')

    @patch('swift3.utils.STORAGE_DOMAIN', None)
    def test_virtual_hosted_style_without_storage_domain(self):
        self.app.register('GET', '/v1/AUTH_X', swob.HTTPOk, {}, '[]')
        req = Request.blank('/',
                            environ={'HTTP_HOST': 'bucket.localhost:80',
                                     'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        m, p = self.app.calls[0]
        self.assertEquals(m, 'GET')
        self.assertEquals(p, '/v1/AUTH_X?format=json')

    @patch('swift3.utils.STORAGE_DOMAIN', '.localhost')
    def test_storage_domain_startswith_dot(self):
        self.test_object_virtual_hosted_style()

    def test_object_virtual_hosted_style_without_http_host(self):
        req = Request.blank('/object',
                            environ={'SERVER_NAME': 'bucket.localhost',
                                     'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        del req.environ['HTTP_HOST']
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_object_create_bad_md5_unreadable(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'PUT',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z',
                                     'HTTP_CONTENT_MD5': '\x07'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')

    def test_invalid_metadata_directive(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z',
                                     'HTTP_X_AMZ_METADATA_DIRECTIVE':
                                     'invalid'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_access_without_remote_user_env(self):
        def update_tenant(env):
            _, authorization = env['HTTP_AUTHORIZATION'].split(' ')
            tenant_user, sign = authorization.rsplit(':', 1)
            tenant, user = tenant_user.rsplit(':', 1)

            path = env['PATH_INFO']
            env['PATH_INFO'] = path.replace(tenant_user, 'AUTH_' + tenant)

        org_func = self.app._fake_auth_middleware
        self.app._fake_auth_middleware = update_tenant
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'SignatureDoesNotMatch')

        self.app._fake_auth_middleware = org_func

    def test_access_with_proxy_access_log_made(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        req.environ['swift.proxy_access_log_made'] = True
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_request_id(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        req.environ['swift.trans_id'] = 'tx0000'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        self.assertEquals(headers['x-amz-id-2'], 'tx0000')
        self.assertEquals(headers['x-amz-request-id'], 'tx0000')

    def test_request_id_error(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'POST',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        req.environ['swift.trans_id'] = 'tx0000'
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MethodNotAllowed')
        self.assertEquals(headers['x-amz-id-2'], 'tx0000')
        self.assertEquals(headers['x-amz-request-id'], 'tx0000')

    def test_unexpected_error(self):
        fn = self.swift3.handle_request
        self.swift3.handle_request = None

        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InternalError')

        self.swift3.handle_request = fn

    def _test_unsupported_header(self, header):
        req = Request.blank('/error',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'},
                            headers={'x-amz-' + header: 'value'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NotImplemented')

    def test_mfa(self):
        self._test_unsupported_header('mfa')

    def test_server_side_encryption(self):
        self._test_unsupported_header('server-side-encryption')

    def test_website_redirect_location(self):
        self._test_unsupported_header('website-redirect-location')

    def _test_unsupported_resource(self, resource):
        req = Request.blank('/error?' + resource,
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'AWS X:Y:Z'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NotImplemented')

    def test_notification(self):
        self._test_unsupported_resource('notification')

    def test_policy(self):
        self._test_unsupported_resource('policy')

    def test_request_payment(self):
        self._test_unsupported_resource('requestPayment')

    def test_torrent(self):
        self._test_unsupported_resource('torrent')

    def test_website(self):
        self._test_unsupported_resource('website')

    def test_cors(self):
        self._test_unsupported_resource('cors')

    def test_tagging(self):
        self._test_unsupported_resource('tagging')

    def test_restore(self):
        self._test_unsupported_resource('restore')
