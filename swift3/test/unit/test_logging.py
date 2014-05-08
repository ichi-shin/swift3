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
from mock import MagicMock, patch
from tempfile import mkdtemp, mkstemp
from shutil import rmtree
import os
import time

from swift.common import swob, wsgi
from swift.common.swob import Request

from swift3.acl import LoggingStatus
from swift3.log_delivery import LogDelivery, NotS3Log
from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.etree import fromstring
from swift3 import log_delivery

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
    '<ID>.log_delivery</ID>' \
    '<DisplayName>log delivery</DisplayName>' \
    '</Grantee>' \
    '<Permission>READ_ACP</Permission>' \
    '</Grant>' \
    '<Grant>' \
    '<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
    'xsi:type="CanonicalUser">' \
    '<ID>.log_delivery</ID>' \
    '<DisplayName>log delivery</DisplayName>' \
    '</Grantee>' \
    '<Permission>WRITE</Permission>' \
    '</Grant>' \
    '</AccessControlList>' \
    '</AccessControlPolicy>'

acl_xml2 = '<?xml version="1.0" encoding="UTF-8"?>' \
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
    '<ID>.log_delivery</ID>' \
    '<DisplayName>log delivery</DisplayName>' \
    '</Grantee>' \
    '<Permission>READ_ACP</Permission>' \
    '</Grant>' \
    '</AccessControlList>' \
    '</AccessControlPolicy>'

conf_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>mybucketlogs</TargetBucket>' \
    '  <TargetPrefix>mybucket-access_log-</TargetPrefix>' \
    '  <TargetGrants>' \
    '   <Grant>' \
    '    <Grantee ' \
    '      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
    '      xsi:type="Group">' \
    '      <URI>http://acs.amazonaws.com/groups/global/' \
    'AuthenticatedUsers</URI>' \
    '     </Grantee>' \
    '     <Permission>READ</Permission>' \
    '   </Grant>' \
    '  </TargetGrants>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

not_found_bucket_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>mybucketlogs2</TargetBucket>' \
    '  <TargetPrefix>mybucket-access_log-</TargetPrefix>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

unauthorized_bucket_xml = \
    '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>mybucketlogs3</TargetBucket>' \
    '  <TargetPrefix>mybucket-access_log-</TargetPrefix>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

not_found_acl_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>mybucketlogs4</TargetBucket>' \
    '  <TargetPrefix>mybucket-access_log-</TargetPrefix>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

unauthorized_acl_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>mybucketlogs5</TargetBucket>' \
    '  <TargetPrefix>mybucket-access_log-</TargetPrefix>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

access_denied_acl_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>mybucketlogs6</TargetBucket>' \
    '  <TargetPrefix>mybucket-access_log-</TargetPrefix>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

log_upload_error_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>mybucketlogs7</TargetBucket>' \
    '  <TargetPrefix>mybucket-access_log-</TargetPrefix>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

acl_upload_error_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>mybucketlogs8</TargetBucket>' \
    '  <TargetPrefix>mybucket-access_log-</TargetPrefix>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

no_acl_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>mybucketlogs</TargetBucket>' \
    '  <TargetPrefix>mybucket-access_log-</TargetPrefix>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

no_prefix_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>mybucketlogs</TargetBucket>' \
    '  <TargetGrants>' \
    '   <Grant>' \
    '    <Grantee ' \
    '      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
    '      xsi:type="Group">' \
    '      <URI>http://acs.amazonaws.com/groups/global/' \
    'AuthenticatedUsers</URI>' \
    '     </Grantee>' \
    '     <Permission>READ</Permission>' \
    '   </Grant>' \
    '  </TargetGrants>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

others_bucket_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>otherbucketlogs</TargetBucket>' \
    '  <TargetPrefix>otherbucket-access_log-</TargetPrefix>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

no_grant_bucket_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
    ' <LoggingEnabled>' \
    '  <TargetBucket>nograntbucketlogs</TargetBucket>' \
    '  <TargetPrefix>nograntbucket-access_log-</TargetPrefix>' \
    ' </LoggingEnabled>' \
    '</BucketLoggingStatus>'

disable_conf_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<BucketLoggingStatus ' \
    ' xmlns="http://doc.s3.amazonaws.com/2006-03-01"/>'

sample_log = 'proxy-server: 127.0.0.1 127.0.0.1 25/Apr/2014/07/51/46' \
    ' POST /object%3Fuploads HTTP/1.0 404 - curl/7.35.0 - - 182 -' \
    ' tx6c514013079842e7a97df-00535a1412 - 0.1013 -' \
    ' requester:test:tester%2Cbucket:bucket%2Ctenant:AUTH_test%2C' \
    'key:object%2Cresource_type:UPLOADS%2Cerror_code:NoSuchBucket%2C' \
    'bucket_ts:0000000001.00000 ' \
    '1398412306.044322014 1398412306.145648956'


class TestSwift3Logging(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Logging, self).setUp()

        self.app.register('HEAD', '/v1/AUTH_test/junk', swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Read': 'test:tester',
                           'X-Container-Write': 'test:tester'}, None)
        self.app.register('GET',
                          '/v1/.swift3/logging_conf/AUTH_test/junk/0',
                          swob.HTTPOk, {}, conf_xml)

        self.app.register('HEAD', '/v1/AUTH_test/no-conf',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'X-Container-Read': 'test:tester',
                           'X-Container-Write': 'test:tester'}, None)
        self.app.register('GET',
                          '/v1/.swift3/logging_conf/AUTH_test/no-conf/0',
                          swob.HTTPNotFound, {}, None)

        # target bucket
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/mybucketlogs/0',
                          swob.HTTPOk, {}, acl_xml)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/mybucketlogs4/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/mybucketlogs5/0',
                          swob.HTTPUnauthorized, {}, None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/mybucketlogs6/0',
                          swob.HTTPOk, {}, acl_xml2)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/mybucketlogs7/0',
                          swob.HTTPOk, {}, acl_xml)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/mybucketlogs8/0',
                          swob.HTTPOk, {}, acl_xml)
        self.app.register('HEAD', '/v1/AUTH_test/mybucketlogs',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'x-container-meta-[swift3]-owner': 'test:tester'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/mybucketlogs3',
                          swob.HTTPUnauthorized,
                          {},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/mybucketlogs4',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'x-container-meta-[swift3]-owner': 'test:tester'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/mybucketlogs5',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'x-container-meta-[swift3]-owner': 'test:tester'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/mybucketlogs6',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'x-container-meta-[swift3]-owner': 'test:tester'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/mybucketlogs7',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'x-container-meta-[swift3]-owner': 'test:tester'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/mybucketlogs8',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'x-container-meta-[swift3]-owner': 'test:tester'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/mybucketlogs2',
                          swob.HTTPNotFound,
                          {},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/otherbucketlogs',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'x-container-meta-[swift3]-owner': 'test:other'},
                          None)
        self.app.register('GET',
                          '/v1/.swift3/acl/AUTH_test/nograntbucketlogs/0',
                          swob.HTTPNotFound, {}, None)
        self.app.register('HEAD', '/v1/AUTH_test/nograntbucketlogs',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'x-container-meta-[swift3]-owner': 'test:tester'},
                          None)

        # NoContent by default
        self.app.register('GET',
                          '/v1/.swift3/logging_conf',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'AUTH_test/junk/0',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'HASH',
                                       'bytes': '100'}]))

        self.app.register('PUT',
                          '/v1/.swift3/logging_conf',
                          swob.HTTPAccepted, {}, None)
        self.app.register('PUT',
                          '/v1/.swift3/logging_conf/AUTH_test/junk/0',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/AUTH_test/mybucketlogs/mybucket-access_log-'
                          '1970-01-01-00-00-00-hash1',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/AUTH_test/mybucketlogs/mybucket-access_log-'
                          '1970-01-01-00-00-00-hash2',
                          swob.HTTPInternalServerError, {}, None)
        self.app.register('PUT',
                          '/v1/AUTH_test/mybucketlogs7/mybucket-access_log-'
                          '1970-01-01-00-00-00-hash1',
                          swob.HTTPBadRequest, {}, None)
        self.app.register('PUT',
                          '/v1/AUTH_test/mybucketlogs8/mybucket-access_log-'
                          '1970-01-01-00-00-00-hash1',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/mybucketlogs/0/'
                          'mybucket-access_log-1970-01-01-00-00-00-hash1/'
                          '1403090918.13405',
                          swob.HTTPCreated, {}, None)
        self.app.register('PUT',
                          '/v1/.swift3/acl/AUTH_test/mybucketlogs8/0/'
                          'mybucket-access_log-1970-01-01-00-00-00-hash1/'
                          '1403090918.13405',
                          swob.HTTPBadRequest, {}, None)

    def test_bucket_logging_GET_error(self):
        bucket_name = 'no-conf'
        req = Request.blank('/%s?logging' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'BucketLoggingStatus')
        self.assertEquals(elem.tag, 'BucketLoggingStatus')
        self.assertEquals(elem.text, None)

    def test_bucket_logging_GET(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?logging' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        elem = fromstring(body, 'BucketLoggingStatus')
        self.assertEquals(elem.tag, 'BucketLoggingStatus')
        self.assertEquals(elem.find('./LoggingEnabled/TargetBucket').text,
                          'mybucketlogs')
        self.assertEquals(elem.find('./LoggingEnabled/TargetPrefix').text,
                          'mybucket-access_log-')
        self.assertEquals(elem.find('./LoggingEnabled/TargetGrants/Grant/'
                                    'Permission').text, 'READ')

    def test_bucket_logging_PUT_error(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?logging' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body='invalid xml')
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_logging_PUT(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?logging' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=conf_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_logging_PUT_other_bucket(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?logging' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=others_bucket_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body),
                          'InvalidTargetBucketForLogging')

    def test_bucket_logging_PUT_no_grant(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?logging' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=no_grant_bucket_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body),
                          'InvalidTargetBucketForLogging')

    def test_bucket_logging_PUT_no_prefix(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?logging' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=no_prefix_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_logging_PUT_no_acl(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?logging' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=no_acl_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_logging_PUT_disable(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?logging' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac'},
                            body=disable_conf_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_log_delivery_error(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        with patch('os.stat') as m:
            with patch('os.unlink'):
                m.return_value.st_mtime = 0

                x = LogDelivery(conf)
                x.get_files_under_log_dir = MagicMock(return_value=['file'])

                x.generate_s3_log = MagicMock()
                x.generate_s3_log.return_value = {
                    ('test:tester', 'junk', '0'): ('line1\nline2\n', 'hash2'),
                }
                x.run_once()

    def test_log_delivery_run_forever(self):
        raises = [0]

        def raise_exceptions():
            raises[0] += 1
            if raises[0] < 2:
                raise Exception('exception %d' % raises[0])
            raise SystemExit('exiting exception %d' % raises[0])

        def not_sleep(seconds):
            pass

        def fake_time():
            return 0

        conf = {
            'log_level': 'debug',
        }

        x = LogDelivery(conf)
        orig_sleep = log_delivery.sleep
        orig_time = log_delivery.time
        try:
            log_delivery.sleep = not_sleep
            log_delivery.time = fake_time
            x.run_once = raise_exceptions
            self.assertRaises(Exception, x.run_forever)
        except SystemExit:
            pass
        finally:
            log_delivery.sleep = orig_sleep
            log_delivery.time = orig_time

    def test_log_delivery(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        with patch('os.stat') as m:
            with patch('os.unlink'):
                m.return_value.st_mtime = 0

                x = LogDelivery(conf)
                x.get_files_under_log_dir = MagicMock(return_value=['file'])

                x.generate_s3_log = MagicMock()
                x.generate_s3_log.return_value = {
                    ('test:tester', 'junk', '0'): ('line1\nline2\n', 'hash1'),
                }
                x.run_once()

    def test_log_delivery_with_conf_xml(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        with patch('os.stat') as m:
            with patch('os.path.getsize') as n:
                with patch('time.time') as o:
                    with patch('os.unlink'):

                        m.return_value.st_mtime = 0
                        n.return_value = 1
                        o.return_value = 1403090918.13405

                        x = LogDelivery(conf)
                        x.get_files_under_log_dir = \
                            MagicMock(return_value=['file'])

                        x.generate_s3_log = MagicMock()
                        x.generate_s3_log.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            ('line1\nline2\n', 'hash1'),
                        }
                        x.get_logging_buckets = MagicMock()
                        x.get_logging_buckets.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            LoggingStatus(conf_xml)}
                        x.owners[('AUTH_test', 'bucket', '0')] = 'test:tester'
                        x.run_once()

    def test_log_delivery_target_bucket_not_found(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }
        with patch('os.stat') as m:
            with patch('os.path.getsize') as n:
                with patch('time.time') as o:
                    with patch('os.unlink'):

                        m.return_value.st_mtime = 0
                        n.return_value = 1
                        o.return_value = 1403090918.13405

                        x = LogDelivery(conf)
                        x.get_files_under_log_dir = \
                            MagicMock(return_value=['file'])

                        x.generate_s3_log = MagicMock()
                        x.generate_s3_log.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            ('line1\nline2\n', 'hash1'),
                        }
                        x.get_logging_buckets = MagicMock()
                        x.get_logging_buckets.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            LoggingStatus(not_found_bucket_xml)}
                        x.owners[('AUTH_test', 'bucket', '0')] = 'test:tester'
                        x.run_once()

    def test_log_delivery_target_bucket_unauthorized(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        with patch('os.stat') as m:
            with patch('os.path.getsize') as n:
                with patch('time.time') as o:
                    with patch('os.unlink'):

                        m.return_value.st_mtime = 0
                        n.return_value = 1
                        o.return_value = 1403090918.13405

                        x = LogDelivery(conf)
                        x.get_files_under_log_dir = \
                            MagicMock(return_value=['file'])

                        x.generate_s3_log = MagicMock()
                        x.generate_s3_log.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            ('line1\nline2\n', 'hash1'),
                        }
                        x.get_logging_buckets = MagicMock()
                        x.get_logging_buckets.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            LoggingStatus(unauthorized_bucket_xml)}
                        x.owners[('AUTH_test', 'bucket', '0')] = 'test:tester'
                        x.run_once()

    def test_log_delivery_acl_not_found(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        with patch('os.stat') as m:
            with patch('os.path.getsize') as n:
                with patch('time.time') as o:
                    with patch('os.unlink'):

                        m.return_value.st_mtime = 0
                        n.return_value = 1
                        o.return_value = 1403090918.13405

                        x = LogDelivery(conf)
                        x.get_files_under_log_dir = \
                            MagicMock(return_value=['file'])

                        x.generate_s3_log = MagicMock()
                        x.generate_s3_log.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            ('line1\nline2\n', 'hash1'),
                        }
                        x.get_logging_buckets = MagicMock()
                        x.get_logging_buckets.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            LoggingStatus(not_found_acl_xml)}
                        x.owners[('AUTH_test', 'bucket', '0')] = 'test:tester'
                        x.run_once()

    def test_log_delivery_acl_unauthorized(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        with patch('os.stat') as m:
            with patch('os.path.getsize') as n:
                with patch('time.time') as o:
                    with patch('os.unlink'):

                        m.return_value.st_mtime = 0
                        n.return_value = 1
                        o.return_value = 1403090918.13405

                        x = LogDelivery(conf)
                        x.get_files_under_log_dir = \
                            MagicMock(return_value=['file'])

                        x.generate_s3_log = MagicMock()
                        x.generate_s3_log.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            ('line1\nline2\n', 'hash1'),
                        }
                        x.get_logging_buckets = MagicMock()
                        x.get_logging_buckets.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            LoggingStatus(unauthorized_acl_xml)}
                        x.owners[('AUTH_test', 'bucket', '0')] = 'test:tester'
                        x.run_once()

    def test_log_delivery_acl_access_denied(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        with patch('os.stat') as m:
            with patch('os.path.getsize') as n:
                with patch('time.time') as o:
                    with patch('os.unlink'):

                        m.return_value.st_mtime = 0
                        n.return_value = 1
                        o.return_value = 1403090918.13405

                        x = LogDelivery(conf)
                        x.get_files_under_log_dir = \
                            MagicMock(return_value=['file'])

                        x.generate_s3_log = MagicMock()
                        x.generate_s3_log.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            ('line1\nline2\n', 'hash1'),
                        }
                        x.get_logging_buckets = MagicMock()
                        x.get_logging_buckets.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            LoggingStatus(access_denied_acl_xml)}
                        x.owners[('AUTH_test', 'bucket', '0')] = 'test:tester'
                        x.run_once()

    def test_log_delivery_log_upload_error(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        with patch('os.stat') as m:
            with patch('os.path.getsize') as n:
                with patch('time.time') as o:
                    with patch('os.unlink'):

                        m.return_value.st_mtime = 0
                        n.return_value = 1
                        o.return_value = 1403090918.13405

                        x = LogDelivery(conf)
                        x.get_files_under_log_dir = \
                            MagicMock(return_value=['file'])

                        x.generate_s3_log = MagicMock()
                        x.generate_s3_log.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            ('line1\nline2\n', 'hash1'),
                        }
                        x.get_logging_buckets = MagicMock()
                        x.get_logging_buckets.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            LoggingStatus(log_upload_error_xml)}
                        x.owners[('AUTH_test', 'bucket', '0')] = 'test:tester'
                        x.run_once()

    def test_log_delivery_acl_upload_error(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        with patch('os.stat') as m:
            with patch('os.path.getsize') as n:
                with patch('time.time') as o:
                    with patch('os.unlink'):

                        m.return_value.st_mtime = 0
                        n.return_value = 1
                        o.return_value = 1403090918.13405

                        x = LogDelivery(conf)
                        x.get_files_under_log_dir = \
                            MagicMock(return_value=['file'])

                        x.generate_s3_log = MagicMock()
                        x.generate_s3_log.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            ('line1\nline2\n', 'hash1'),
                        }
                        x.get_logging_buckets = MagicMock()
                        x.get_logging_buckets.return_value = {
                            ('AUTH_test', 'bucket', '0'):
                            LoggingStatus(acl_upload_error_xml)}
                        x.owners[('AUTH_test', 'bucket', '0')] = 'test:tester'
                        x.run_once()

    def test_log_delivery_logging_conf_not_found(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        self.app.register('GET',
                          '/v1/.swift3/logging_conf',
                          swob.HTTPNotFound, {}, None)

        with patch('os.stat') as m:
            with patch('os.path.getsize') as n:
                with patch('time.time') as o:

                    m.return_value.st_mtime = 0
                    n.return_value = 1
                    o.return_value = 1403090918.13405

                    x = LogDelivery(conf)
                    x.get_files_under_log_dir = \
                        MagicMock(return_value=['file'])

                    x.generate_s3_log = MagicMock()
                    x.generate_s3_log.return_value = {
                        ('AUTH_test2', 'bucket', '0'):
                        ('line1\nline2\n', 'hash1'),
                    }
                    x.run_once()

    def test_log_delivery_logging_conf_owner_not_found(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        self.app.register('GET',
                          '/v1/.swift3/logging_conf/AUTH_test/junk/0',
                          swob.HTTPNotFound, {}, None)

        with patch('os.stat') as m:
            with patch('os.path.getsize') as n:
                with patch('time.time') as o:

                    m.return_value.st_mtime = 0
                    n.return_value = 1
                    o.return_value = 1403090918.13405

                    x = LogDelivery(conf)
                    x.get_files_under_log_dir = \
                        MagicMock(return_value=['file'])

                    x.generate_s3_log = MagicMock()
                    x.generate_s3_log.return_value = {
                        ('AUTH_test', 'bucket', '0'):
                        ('line1\nline2\n', 'hash1'),
                    }
                    x.run_once()

    def test_log_delivery_os_error(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        with patch('os.stat') as m:
            with patch('os.unlink'):
                m.side_effect = OSError

                x = LogDelivery(conf)
                x.get_files_under_log_dir = MagicMock(return_value=['file'])

                x.generate_s3_log = MagicMock()
                x.generate_s3_log.return_value = {
                    ('test:tester', 'junk', '0'): ('line1\nline2\n', 'hash1'),
                }
                x.run_once()

    def test_log_delivery_unlink_error(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }

        with patch('os.stat') as m:
            with patch('os.unlink') as n:
                m.return_value.st_mtime = 0
                n.side_effect = Exception

                x = LogDelivery(conf)
                x.get_files_under_log_dir = MagicMock(return_value=['file'])

                x.generate_s3_log = MagicMock()
                x.generate_s3_log.return_value = {
                    ('test:tester', 'junk', '0'): ('line1\nline2\n', 'hash1'),
                }
                x.run_once()

    def test_log_delivery_skip_alllog(self):
        wsgi.loadapp = lambda *a, **kw: self.app

        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
            'log_delivery_new_log_cutoff': 1000000,
        }

        with patch('os.stat') as m:
            with patch('os.unlink'):
                m.return_value.st_mtime = int(time.time())

                x = LogDelivery(conf)
                x.get_files_under_log_dir = MagicMock(return_value=['file'])

                x.generate_s3_log = MagicMock()
                x.generate_s3_log.return_value = {
                    ('test:tester', 'junk', '0'): ('line1\nline2\n', 'hash1'),
                }
                x.run_once()

    def test_log_delivery_walk_dir(self):
        testdir = mkdtemp()
        conf = {
            'log_delivery_dir': testdir
        }

        (_, log1) = mkstemp(dir=testdir)
        (_, log2) = mkstemp(dir=testdir)
        (_, log3) = mkstemp(dir=testdir)
        x = LogDelivery(conf)

        self.assertEquals(list([log1, log2, log3]).sort(),
                          list(x.get_files_under_log_dir()).sort())

        rmtree(testdir, ignore_errors=1)

    def test_log_delivery_translate_line(self):
        x = LogDelivery({})
        log = x.translate_line(sample_log)
        self.assertEquals(log, (('AUTH_test', 'bucket', '0000000001.00000'),
                                ('-', 'bucket', '25/Apr/2014/07/51/46',
                                 '127.0.0.1', 'test:tester',
                                 'tx6c514013079842e7a97df-00535a1412',
                                 'REST.POST.UPLOADS', 'object',
                                 '"POST /object?uploads"', '404',
                                 'NoSuchBucket', '182', '-', '101', '-', '-',
                                 'curl/7.35.0', '-')))

    def test_log_delivery_translate_non_s3_line(self):
        x = LogDelivery({})
        self.assertRaises(NotS3Log, x.translate_line, 'not s3 log')

    def test_log_delivery_translate_wrong_line(self):
        x = LogDelivery({})
        self.assertRaises(NotS3Log, x.translate_line, '')

    def test_log_delivery_translate_wrong_no_bucket_ts(self):
        line = 'proxy-server: 127.0.0.1 127.0.0.1 25/Apr/2014/07/51/46' \
            ' POST /object%3Fuploads HTTP/1.0 404 - curl/7.35.0 - - 182 -' \
            ' tx6c514013079842e7a97df-00535a1412 - 0.1013 -' \
            ' requester:test:tester%2Cbucket:bucket%2Ctenant:AUTH_test%2C' \
            'key:object%2Cresource_type:UPLOADS%2Cerror_code:NoSuchBucket ' \
            '1398412306.044322014 1398412306.145648956'
        x = LogDelivery({})
        self.assertRaises(NotS3Log, x.translate_line, line)

    def test_log_delivery_generate_s3_log(self):
        (_, log) = mkstemp()

        f = open(log, 'w')
        f.write(sample_log)
        f.close()

        self.maxDiff = None
        x = LogDelivery({})
        logdata = x.generate_s3_log(log)

        self.assertEquals(logdata, {
            ('AUTH_test', 'bucket', '0000000001.00000'):
            ('- bucket 25/Apr/2014/07/51/46 127.0.0.1 test:tester '
             'tx6c514013079842e7a97df-00535a1412 REST.POST.UPLOADS '
             'object "POST /object?uploads" 404 NoSuchBucket 182 - '
             '101 - - curl/7.35.0 -\n',
             'd4ce3b3b5a12fa70d9796be93b99b67b'
             )
        })

        os.remove(log)

    def test_log_delivery_head_object(self):
        wsgi.loadapp = lambda *a, **kw: self.app
        conf = {
            'log_level': 'debug',
            'log_delivery_dir': '/tmp/swift/log/',
        }
        self.app.register('HEAD', '/v1/AUTH_test/bucket/object',
                          swob.HTTPNoContent,
                          {'x-container-meta-[swift3]-timestamp': 0,
                           'x-container-meta-[swift3]-owner': 'test:tester'},
                          None)
        x = LogDelivery(conf)
        resp = x.head_object('AUTH_test', 'bucket', 'object')
        self.assertEquals(204, resp.status_int)

    def test_log_delivery_generate_s3_log_for_non_s3_log(self):
        (_, log) = mkstemp()

        f = open(log, 'w')
        f.write('not s3 log\n')
        f.close()

        x = LogDelivery({})
        log_data = x.generate_s3_log(log)
        os.remove(log)

        self.assertEquals(log_data, {})

    @patch('os.path.getsize', lambda x: 0)
    def test_zero_size_log(self):
        logs = ['']

        def log(s):
            logs[0] += s

        x = LogDelivery({})

        fn = x.logger.debug
        x.logger.debug = log
        x.generate_s3_log('dummy')
        x.logger.debug = fn

        self.assertEquals(logs[0], 'Log dummy is 0 length, skipping')
