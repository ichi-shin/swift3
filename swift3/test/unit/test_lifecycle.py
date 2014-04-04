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
import md5

from swift.common import swob, wsgi
from swift.common.swob import Request

from swift3.etree import Element, SubElement, tostring, fromstring
from swift3.test.unit.test_middleware import Swift3TestCase
from swift3.expirer import ObjectExpirer
from swift3 import expirer, utils
from swift3.subresource import Lifecycle
from swift3.response import MalformedXML, InvalidArgument, InvalidRequest
from swift3.exception import ExpirerError


conf_xml = '<LifecycleConfiguration>' \
    '  <Rule>' \
    '    <ID>delete-just-after-creation</ID>' \
    '    <Prefix>a</Prefix>' \
    '    <Status>Enabled</Status>' \
    '    <Expiration>' \
    '      <Days>0</Days>' \
    '    </Expiration>' \
    '  </Rule>' \
    '  <Rule>' \
    '    <Prefix>b</Prefix>' \
    '    <Status>Enabled</Status>' \
    '    <Expiration>' \
    '      <Date>2022-10-12T00:00:00.000Z</Date>' \
    '    </Expiration>' \
    '  </Rule>' \
    '  <Rule>' \
    '    <Prefix>c</Prefix>' \
    '    <Status>Disabled</Status>' \
    '    <Expiration>' \
    '      <Date>2022-10-12T00:00:00.000Z</Date>' \
    '    </Expiration>' \
    '  </Rule>' \
    '</LifecycleConfiguration>'

invalid_conf_xml = '<LifecycleConfiguration>' \
    '  <Rule>' \
    '    <ID>delete-just-after-creation</ID>' \
    '    <Prefix>a</Prefix>' \
    '    <Status>Enabled</Status>' \
    '    <Expiration>' \
    '      <Dayss>0</Dayss>' \
    '    </Expiration>' \
    '  </Rule>' \
    '</LifecycleConfiguration>'

invalid_date_conf_xml = '<LifecycleConfiguration>' \
    '  <Rule>' \
    '    <ID>delete-just-after-creation</ID>' \
    '    <Prefix>a</Prefix>' \
    '    <Status>Enabled</Status>' \
    '    <Expiration>' \
    '      <Date>20221012T00:00:00</Date>' \
    '    </Expiration>' \
    '  </Rule>' \
    '</LifecycleConfiguration>'

non_midnight_xml = '<LifecycleConfiguration>' \
    '  <Rule>' \
    '    <ID>delete-just-after-creation</ID>' \
    '    <Prefix>a</Prefix>' \
    '    <Status>Enabled</Status>' \
    '    <Expiration>' \
    '      <Date>2022-10-12T00:00:01</Date>' \
    '    </Expiration>' \
    '  </Rule>' \
    '</LifecycleConfiguration>'

transition_xml = '<LifecycleConfiguration>' \
    '  <Rule>' \
    '    <ID>delete-just-after-creation</ID>' \
    '    <Prefix>a</Prefix>' \
    '    <Status>Enabled</Status>' \
    '    <Transition>' \
    '      <Days>0</Days>' \
    '      <StorageClass>GLACIER</StorageClass>' \
    '    </Transition>' \
    '  </Rule>' \
    '</LifecycleConfiguration>'

no_prefix_xml = '<LifecycleConfiguration>' \
    '  <Rule>' \
    '    <ID>delete-just-after-creation</ID>' \
    '    <Status>Enabled</Status>' \
    '    <Expiration>' \
    '      <Days>0</Days>' \
    '    </Expiration>' \
    '  </Rule>' \
    '</LifecycleConfiguration>'

invalid_status_xml = '<LifecycleConfiguration>' \
    '  <Rule>' \
    '    <ID>delete-just-after-creation</ID>' \
    '    <Prefix>a</Prefix>' \
    '    <Status>Suspended</Status>' \
    '    <Expiration>' \
    '      <Days>0</Days>' \
    '    </Expiration>' \
    '  </Rule>' \
    '</LifecycleConfiguration>'

no_expiration_xml = '<LifecycleConfiguration>' \
    '  <Rule>' \
    '    <ID>delete-just-after-creation</ID>' \
    '    <Prefix>a</Prefix>' \
    '    <Status>Enabled</Status>' \
    '  </Rule>' \
    '</LifecycleConfiguration>'

conf_same_id_xml = '<LifecycleConfiguration>' \
    '  <Rule>' \
    '    <ID>id</ID>' \
    '    <Prefix>a</Prefix>' \
    '    <Status>Enabled</Status>' \
    '    <Expiration>' \
    '      <Days>0</Days>' \
    '    </Expiration>' \
    '  </Rule>' \
    '  <Rule>' \
    '    <ID>id</ID>' \
    '    <Prefix>b</Prefix>' \
    '    <Status>Enabled</Status>' \
    '    <Expiration>' \
    '      <Date>2022-10-12T00:00:00.000Z</Date>' \
    '    </Expiration>' \
    '  </Rule>' \
    '</LifecycleConfiguration>'

conf_overlapping_prefixes_xml = '<LifecycleConfiguration>' \
    '  <Rule>' \
    '    <Prefix>x</Prefix>' \
    '    <Status>Enabled</Status>' \
    '    <Expiration>' \
    '      <Date>2022-10-12T00:00:00.000Z</Date>' \
    '    </Expiration>' \
    '  </Rule>' \
    '  <Rule>' \
    '    <Prefix>xyz</Prefix>' \
    '    <Status>Disabled</Status>' \
    '    <Expiration>' \
    '      <Date>2022-10-12T00:00:00.000Z</Date>' \
    '    </Expiration>' \
    '  </Rule>' \
    '</LifecycleConfiguration>'


class TestSwift3Lifecycle(Swift3TestCase):

    def setUp(self):
        super(TestSwift3Lifecycle, self).setUp()

        self.app.register('HEAD', '/v1/AUTH_test/junk', swob.HTTPNoContent,
                          {'x-timestamp': 0,
                           'x-container-sysmeta-swift3-acl': '["test:tester"]',
                           'x-container-sysmeta-swift3-lifecycle':
                           '[["delete-just-after-creation","a",1,"",0],'
                           '["X","b",1,"","2022-10-12"],'
                           '["Y","c",0,"","2022-10-12"]]'},
                          None)
        self.app.register('POST', '/v1/AUTH_test/junk', swob.HTTPNoContent,
                          {}, None)
        self.app.register('HEAD', '/v1/AUTH_test/versioned',
                          swob.HTTPNoContent,
                          {'x-timestamp': 0,
                           'x-container-sysmeta-swift3-acl': '["test:tester"]',
                           'x-container-sysmeta-swift3-Versioning':
                           '"Enabled"'},
                          None)
        self.app.register('GET', '/v1/AUTH_test?format=json',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'junk',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 0},
                                      {'name': 'junk_deleted',
                                       'last_modified':
                                       '2014-05-07T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 0}
                                      ]))
        self.app.register('GET',
                          '/v1/AUTH_test/junk?format=json',
                          swob.HTTPOk,
                          {'x-timestamp': 0},
                          json.dumps([{'name': 'a1',
                                       'last_modified':
                                       '1970-01-01T00:00:01.000000',
                                       'hash': 'Y',
                                       'bytes': 0},
                                      {'name': 'a2',
                                       'last_modified':
                                       '1970-01-01T00:00:01.000000',
                                       'hash': 'Y',
                                       'bytes': 0}]))
        self.app.register('HEAD',
                          '/v1/AUTH_test/junk_deleted',
                          swob.HTTPNoContent,
                          {'x-timestamp': 0,
                           'x-container-sysmeta-swift3-acl': '["test:tester"]',
                           'x-container-sysmeta-swift3-has-lifecycle': 'true'},
                          None)
        self.app.register('GET',
                          '/v1/AUTH_test/junk_deleted?format=json',
                          swob.HTTPOk,
                          {'x-timestamp': 0,
                           'x-container-sysmeta-swift3-has-lifecycle': 'true'},
                          json.dumps([]))
        # succeed in reclaiming
        self.app.register('HEAD', '/v1/AUTH_test/junk/a1',
                          swob.HTTPOk,
                          {'x-timestamp': 0,
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/junk/a2',
                          swob.HTTPOk,
                          {'x-timestamp': 0,
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('HEAD', '/v1/AUTH_test/junk/b1',
                          swob.HTTPOk,
                          {'x-timestamp': 0,
                           'x-object-meta-[swift3]-acl': '["test:tester"]'},
                          None)
        self.app.register('DELETE', '/v1/AUTH_test/junk/a1',
                          swob.HTTPNoContent, {}, None)
        # fail to reclaim
        self.app.register('DELETE', '/v1/AUTH_test/junk/a2',
                          swob.HTTPNotFound, {}, None)

    def test_bucket_lifecycle_GET(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')
        print body
        elem = fromstring(body, 'LifecycleConfiguration')
        self.assertEquals(elem.tag, 'LifecycleConfiguration')
        rules = list(elem.iterchildren('Rule'))

        self.assertEquals(rules[0].find('./ID').text,
                          'delete-just-after-creation')
        self.assertEquals(rules[0].find('./Prefix').text, 'a')
        self.assertEquals(rules[1].find('./Prefix').text, 'b')
        self.assertEquals(rules[0].find('./Status').text, 'Enabled')
        self.assertEquals(rules[0].find('./Expiration/Days').text, '0')

    def test_bucket_lifecycle_GET_after_DELETE(self):
        bucket_name = 'junk_deleted'
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(self._get_error_code(body),
                          'NoSuchLifecycleConfiguration')

    def test_bucket_lifecycle_PUT_invalid_xml(self):
        bucket_name = 'junk'
        body = 'invalid_xml'
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_lifecycle_PUT_zero_rule(self):
        bucket_name = 'junk'
        body = '<LifecycleConfiguration/>'
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        status, headers, body = self.call_swift3(req)
        print body
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_lifecycle_PUT_invalid_digest(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': 'invalidmd5'},
                            body=conf_xml)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidDigest')

    def test_bucket_lifecycle_PUT_to_versioned_bucket(self):
        bucket_name = 'versioned'
        body = conf_xml
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidBucketState')

    def test_bucket_lifecycle_PUT(self):
        t = [0]

        def mock_normalize_timestamp():
            t[0] += 1
            return "%016.05f" % (float(t[0]))

        bucket_name = 'junk'
        body = conf_xml
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        utils.normalized_currrent_timestamp = mock_normalize_timestamp
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_lifecycle_PUT_error(self):
        t = [0]

        def mock_normalize_timestamp():
            t[0] += 1
            return "%016.05f" % (float(t[0]))

        bucket_name = 'junk'
        body = 'invalid'
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        utils.normalized_currrent_timestamp = mock_normalize_timestamp
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_lifecycle_PUT_invalid_expiration(self):
        t = [0]

        def mock_normalize_timestamp():
            t[0] += 1
            return "%016.05f" % (float(t[0]))

        bucket_name = 'junk'
        body = invalid_conf_xml
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        utils.normalized_currrent_timestamp = mock_normalize_timestamp
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_lifecycle_PUT_invalid_date(self):
        t = [0]

        def mock_normalize_timestamp():
            t[0] += 1
            return "%016.05f" % (float(t[0]))

        bucket_name = 'junk'
        body = invalid_date_conf_xml
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        utils.normalized_currrent_timestamp = mock_normalize_timestamp
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_lifecycle_PUT_non_midnight(self):
        t = [0]

        def mock_normalize_timestamp():
            t[0] += 1
            return "%016.05f" % (float(t[0]))

        bucket_name = 'junk'
        body = non_midnight_xml
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        utils.normalized_currrent_timestamp = mock_normalize_timestamp
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_lifecycle_PUT_transition(self):
        t = [0]

        def mock_normalize_timestamp():
            t[0] += 1
            return "%016.05f" % (float(t[0]))

        bucket_name = 'junk'
        body = transition_xml
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        utils.normalized_currrent_timestamp = mock_normalize_timestamp
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'NotImplemented')

    def test_bucket_lifecycle_PUT_no_prefix(self):
        t = [0]

        def mock_normalize_timestamp():
            t[0] += 1
            return "%016.05f" % (float(t[0]))

        bucket_name = 'junk'
        body = no_prefix_xml
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        utils.normalized_currrent_timestamp = mock_normalize_timestamp
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_lifecycle_PUT_invalid_status(self):
        t = [0]

        def mock_normalize_timestamp():
            t[0] += 1
            return "%016.05f" % (float(t[0]))

        bucket_name = 'junk'
        body = invalid_status_xml
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        utils.normalized_currrent_timestamp = mock_normalize_timestamp
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'MalformedXML')

    def test_bucket_lifecycle_PUT_no_expiration(self):
        t = [0]

        def mock_normalize_timestamp():
            t[0] += 1
            return "%016.05f" % (float(t[0]))

        bucket_name = 'junk'
        body = no_expiration_xml
        digest = md5.new(body).digest().encode('base64')[:-1]
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Content-MD5': digest},
                            body=body)
        utils.normalized_currrent_timestamp = mock_normalize_timestamp
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'InvalidArgument')

    def test_bucket_lifecycle_DELETE(self):
        def mock_normalize_timestamp():
            return "%016.05f" % 1.0

        bucket_name = 'junk'
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        utils.normalized_currrent_timestamp = mock_normalize_timestamp
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '204')

    def test_object_expirer_bucket_not_found(self):
        wsgi.loadapp = lambda *a, **kw: self.app
        conf = {
            'log_level': 'debug',
        }

        self.app.register('GET',
                          '/v1/AUTH_test/junk?format=json',
                          swob.HTTPNotFound, {}, None)

        ObjectExpirer(conf).run_once()

    def test_object_expirer_bucket_bad_request(self):
        wsgi.loadapp = lambda *a, **kw: self.app
        conf = {
            'log_level': 'debug',
        }

        self.app.register('GET',
                          '/v1/AUTH_test/junk?format=json',
                          swob.HTTPBadRequest, {}, None)

        self.assertRaises(ExpirerError, ObjectExpirer(conf).run_once)

    def test_object_expirer_object_not_found(self):
        wsgi.loadapp = lambda *a, **kw: self.app
        conf = {
            'log_level': 'debug',
        }

        self.app.register('HEAD',
                          '/v1/AUTH_test/junk/a1',
                          swob.HTTPNotFound, {}, None)

        self.assertRaises(ExpirerError, ObjectExpirer(conf).run_once)

    def test_object_expirer_object_without_timestamp(self):
        wsgi.loadapp = lambda *a, **kw: self.app
        conf = {
            'log_level': 'debug',
        }

        self.app.register('HEAD',
                          '/v1/AUTH_test/junk/a1',
                          swob.HTTPNoContent,
                          {'X-Timestamp': 0}, None)
        self.app.register('DELETE', '/v1/AUTH_test/junk/a2',
                          swob.HTTPNoContent, {}, None)

        ObjectExpirer(conf).run_once()

    def test_object_expirer_rule_bucket_not_found(self):
        wsgi.loadapp = lambda *a, **kw: self.app
        conf = {
            'log_level': 'debug',
        }

        self.app.register('GET', '/v1/AUTH_test?format=json',
                          swob.HTTPNotFound, {}, None)

        self.assertRaises(ExpirerError, ObjectExpirer(conf).run_once)

    def test_object_expirer_object_report_time(self):
        wsgi.loadapp = lambda *a, **kw: self.app
        conf = {
            'log_level': 'debug',
        }

        self.app.register('HEAD',
                          '/v1/AUTH_test/junk/a1',
                          swob.HTTPNoContent,
                          {'x-timestamp': 0}, None)
        self.app.register('DELETE', '/v1/AUTH_test/junk/a2',
                          swob.HTTPNoContent,
                          {'x-timestamp': 0}, None)

        x = ObjectExpirer(conf)
        x.report_interval = 0
        x.run_once()

    def test_object_expirer_object_rules(self):
        wsgi.loadapp = lambda *a, **kw: self.app
        conf = {
            'log_level': 'debug',
        }

        self.app.register('GET', '/v1/AUTH_test?format=json',
                          swob.HTTPOk, {},
                          json.dumps([{'name': 'junk',
                                       'last_modified':
                                       '2014-05-08T19:47:54.592270',
                                       'hash': 'Y',
                                       'bytes': 'Z'}
                                      ]))
        self.app.register('HEAD', '/v1/AUTH_test/junk/a1',
                          swob.HTTPNoContent,
                          {'x-timestamp': 0}, None)
        self.app.register('DELETE', '/v1/AUTH_test/junk/a2',
                          swob.HTTPNoContent,
                          {'x-timestamp': 0}, None)

        x = ObjectExpirer(conf)
        x.run_once()

    def test_object_expirer_run_forever(self):
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

        x = ObjectExpirer(conf)
        orig_sleep = expirer.sleep
        orig_time = expirer.time
        try:
            expirer.sleep = not_sleep
            expirer.time = fake_time
            x.run_once = raise_exceptions
            x.run_forever()
        except SystemExit:
            pass
        finally:
            expirer.sleep = orig_sleep
            expirer.time = orig_time

    def test_object_expirer_run_forever_expirer_error(self):
        raises = [0]

        def raise_exceptions():
            raises[0] += 1
            if raises[0] < 2:
                raise ExpirerError('exception %d' % raises[0])
            raise SystemExit('exiting exception %d' % raises[0])

        def not_sleep(seconds):
            pass

        def fake_time():
            return 0

        conf = {
            'log_level': 'debug',
        }

        x = ObjectExpirer(conf)
        orig_sleep = expirer.sleep
        orig_time = expirer.time
        try:
            expirer.sleep = not_sleep
            expirer.time = fake_time
            x.run_once = raise_exceptions
            x.run_forever()
        except SystemExit:
            pass
        finally:
            expirer.sleep = orig_sleep
            expirer.time = orig_time

    def test_too_many_rules(self):
        def add_rule(parent, rule_id):
            rule_elem = SubElement(parent, 'Rule')
            SubElement(rule_elem, 'ID').text = rule_id
            SubElement(rule_elem, 'Prefix').text = rule_id
            SubElement(rule_elem, 'Status').text = 'Enabled'
            expire_elem = SubElement(rule_elem, 'Expiration')
            SubElement(expire_elem, 'Days').text = '1'

        conf_elem = Element('LifecycleConfiguration')
        for n in range(1000):
            rule_id = 'rule%d_id' % n
            add_rule(conf_elem, rule_id)

        xml = tostring(conf_elem)
        Lifecycle(xml)

        add_rule(conf_elem, 'rule1001_id')
        xml = tostring(conf_elem)
        self.assertRaises(MalformedXML, Lifecycle, xml)

    def test_same_id_rules(self):
        self.assertRaises(InvalidArgument, Lifecycle, xml=conf_same_id_xml)

    def test_overlapping_prefixes_rules(self):
        self.assertRaises(InvalidRequest, Lifecycle,
                          xml=conf_overlapping_prefixes_xml)

    def test_expiration_header(self):
        req = Request.blank('/junk/b1',
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(status.split()[0], '200')

    def test_bucket_lifecycle_owner_error(self):
        bucket_name = 'junk'
        req = Request.blank('/%s?lifecycle' % bucket_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:user:hmac'})
        status, headers, body = self.call_swift3(req)
        self.assertEquals(self._get_error_code(body), 'AccessDenied')
