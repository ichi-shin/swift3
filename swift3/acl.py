# Copyright (c) 2014 OpenStack Foundation.
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

import re
from swift3.etree import Element, SubElement, fromstring, tostring
from datetime import datetime
import time
import calendar

from swift3.response import S3ErrorResponse, InvalidArgument, \
    MalformedACLError, MalformedXML, NotImplemented, UnexpectedContent, \
    InvalidRequest, MissingSecurityHeader
from swift3 import utils

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'


class Grantee(object):
    def __init__(self, type):
        self.type = type

    def add_xml_element(self, parent):
        grantee_elem = SubElement(parent, 'Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee_elem.set('xsi:type', self.type)
        return grantee_elem


class User(Grantee):
    def __init__(self, name):
        Grantee.__init__(self, 'CanonicalUser')
        self.id = name
        self.display_name = name

    def __contains__(self, key):
        return key == self.id

    def __str__(self):
        return self.display_name

    def add_xml_element(self, parent):
        grantee_elem = Grantee.add_xml_element(self, parent)
        SubElement(grantee_elem, 'ID').text = self.id
        SubElement(grantee_elem, 'DisplayName').text = self.display_name
        return grantee_elem


acceptable_groups = {}


def group_uri(uri):
    def _group_uri(cls):
        cls.uri = uri
        acceptable_groups.update({uri: cls()})
        return cls
    return _group_uri


canned_acls = {}


def canned_acl(acl):
    def _canned_acl(cls):
        canned_acls.update({acl: cls()})
        return cls
    return _canned_acl


class Group(Grantee):
    def __init__(self):
        Grantee.__init__(self, 'Group')

    def __str__(self):
        name = re.sub('(.)([A-Z])', r'\1 \2', self.__class__.__name__)
        return name + ' group'

    def add_xml_element(self, parent):
        grantee_elem = Grantee.add_xml_element(self, parent)
        SubElement(grantee_elem, 'URI').text = self.uri
        return grantee_elem


@group_uri('http://acs.amazonaws.com/groups/global/AuthenticatedUsers')
class AuthenticatedUsers(Group):
    def __contains__(self, key):
        # All requests should be from authenticated users.
        return True


@group_uri('http://acs.amazonaws.com/groups/global/AllUsers')
class AllUsers(Group):
    def __contains__(self, key):
        return True


@group_uri('http://acs.amazonaws.com/groups/s3/LogDelivery')
class LogDelivery(Group):
    def __contains__(self, key):
        if ':' in key:
            tenant, user = key.split(':', 1)
        else:
            user = key
        return user == utils.LOG_DELIVERY_USER


class Owner(Grantee):
    def __init__(self):
        Grantee.__init__(self, 'CanonicalUser')

    def to_user(self, bucket_owner, object_owner=None):
        if object_owner:
            return User(object_owner)
        else:
            return User(bucket_owner)


class BucketOwner(Owner):
    def to_user(self, bucket_owner, object_owner):
        return Owner.to_user(self, bucket_owner, None)


# TODO: create XML class and move this method into it
def parse_grant_elem(grant_elem):
    grantee_elem = grant_elem.find('./Grantee')
    type = grantee_elem.get('xsi:type')
    if type == 'Group':
        uri_elem = grantee_elem.find('./URI')
        if uri_elem.text in acceptable_groups:
            grantee = acceptable_groups[uri_elem.text]
        else:
            raise InvalidArgument('Group/URI', uri_elem.text,
                                  'Invalid group uri')
    elif type == 'CanonicalUser':
        id_elem = grantee_elem.find('./ID')
        grantee = User(id_elem.text)
    elif type == 'AmazonCustomerByEmail':
        raise NotImplemented()
    else:
        raise Exception('invalide type "%s"' % type)

    permission = grant_elem.find('./Permission').text

    return permission, grantee


class ACL(object):
    """
    S3 ACL
    """
    acceptable_permissions = (
        'READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'
    )

    """
    grant: list of (permission, grantee)
    """
    def __init__(self, grant=None, headers=None, xml=None):
        self.grant = grant if grant else []
        self.owner = None

        if headers:
            header_grant = self._parse_headers(headers)
            if len(header_grant) > 0 and xml:
                # Specifying granth with both header and xml is not allowed
                raise UnexpectedContent()
            self.grant.extend(header_grant)
        if xml:
            self._parse_xml(xml)

        if grant is None and not self.grant:
            if xml is None:
                # private by default
                self.grant = ACLPrivate().grant
            elif xml == '':
                # ACL headers must be specified in this case (e.g. PUT ACL
                # requests)
                msg = 'Your request was missing a required header'
                raise MissingSecurityHeader(msg,
                                            missing_header_name='x-amz-acl')

        self._validate_grant()

    def _validate_grant(self):
        if len(self.grant) > utils.MAX_ACL_GRANTS:
            raise MalformedACLError()

        for permission, _ in self.grant:
            if permission not in self.acceptable_permissions:
                raise MalformedACLError()

    def _parse_headers(self, headers):
        try:
            grant = []
            for key, value in headers.items():
                if key.lower().startswith('x-amz-grant-'):
                    perm = key[len('x-amz-grant-'):].upper().replace('-', '_')
                    for grantee in self._parse_grantees(value):
                        grant.append((perm, grantee))

            if 'x-amz-acl' in headers:
                if len(grant) > 0:
                    err_msg = 'Specifying both Canned ACLs and Header ' \
                        'Grants is not allowed'
                    raise InvalidRequest(err_msg)
                acl = canned_acls[headers['x-amz-acl']]
                grant = acl.grant

            return grant
        except (KeyError, ValueError):
            raise InvalidRequest()

    def _parse_xml(self, xml):
        try:
            acp_elem = fromstring(xml, 'AccessControlPolicy')
            owner_elem = acp_elem.find('./Owner')
            self.owner = owner_elem.find('./ID').text

            acl_elem = acp_elem.find('./AccessControlList')

            for grant_elem in acl_elem.iterchildren('Grant'):
                self.grant.append(parse_grant_elem(grant_elem))
        except S3ErrorResponse:
            raise
        except Exception as e:
            print e  # FIXME: use logger
            raise MalformedACLError()

    def _parse_grantee(self, grantee):
        type, value = grantee.split('=', 1)
        value = value.strip('"\'')
        if type == 'id':
            return User(value)
        elif type == 'emailAddress':
            raise NotImplemented()
        elif type == 'uri':
            if value in acceptable_groups:
                return acceptable_groups[value]
            else:
                raise InvalidArgument(type, value, 'Invalid group uri')
        else:
            raise InvalidArgument(type, value,
                                  'Argument format not recognized')

    def _parse_grantees(self, grantees):
        return [self._parse_grantee(g) for g in grantees.split(',')]

    def acl_iter(self, bucket_owner, object_owner):
        # Owner name will be resolved
        for permission, grantee in self.grant:
            if isinstance(grantee, Owner):
                grantee = grantee.to_user(bucket_owner, object_owner)

            yield permission, grantee

    def __iter__(self):
        return iter(self.grant)

    def __getitem__(self, key):
        grant = [(p, g) for (p, g) in self.grant if p.lower() == key.lower()]
        return ACL(grant)

    def __contains__(self, key):
        for permission, grantee in self.grant:
            if not utils.ALLOW_CONTAINER_PUBLIC_WRITE:
                # skip public write permission
                if permission == 'WRITE' and isinstance(grantee, AllUsers):
                    continue
            if key in grantee:
                return True

        return False

    def to_xml(self, bucket_owner, object_owner=None):
        owner = object_owner if object_owner else bucket_owner
        acp_elem = Element('AccessControlPolicy')

        owner_elem = SubElement(acp_elem, 'Owner')
        SubElement(owner_elem, 'ID').text = owner
        SubElement(owner_elem, 'DisplayName').text = owner

        acl_elem = SubElement(acp_elem, 'AccessControlList')
        for permission, grantee in self.acl_iter(bucket_owner, object_owner):
            grant_elem = SubElement(acl_elem, 'Grant')
            grantee.add_xml_element(grant_elem)
            SubElement(grant_elem, 'Permission').text = permission

        return tostring(acp_elem)


@canned_acl('private')
class ACLPrivate(ACL):
    def __init__(self):
        acl = [
            ('FULL_CONTROL', Owner()),
        ]
        ACL.__init__(self, acl)


@canned_acl('public-read')
class ACLPublicRead(ACL):
    def __init__(self):
        acl = [
            ('READ', AllUsers()),
            ('FULL_CONTROL', Owner()),
        ]
        ACL.__init__(self, acl)


@canned_acl('public-read-write')
class ACLPublicReadWrite(ACL):
    def __init__(self):
        acl = [
            ('READ', AllUsers()),
            ('WRITE', AllUsers()),
            ('FULL_CONTROL', Owner()),
        ]
        ACL.__init__(self, acl)


@canned_acl('authenticated-read')
class ACLAuthenticatedRead(ACL):
    def __init__(self):
        acl = [
            ('READ', AuthenticatedUsers()),
            ('FULL_CONTROL', Owner()),
        ]
        ACL.__init__(self, acl)


@canned_acl('bucket-owner-read')
class ACLBucketOwnerRead(ACL):
    def __init__(self):
        acl = [
            ('READ', BucketOwner()),
            ('FULL_CONTROL', Owner()),
        ]
        ACL.__init__(self, acl)


@canned_acl('bucket-owner-full-control')
class ACLBucketOwnerFullControll(ACL):
    def __init__(self):
        acl = [
            ('FULL_CONTROL', Owner()),
            ('FULL_CONTROL', BucketOwner()),
        ]
        ACL.__init__(self, acl)


@canned_acl('log-delivery-write')
class ACLLogDeliveryWrite(ACL):
    def __init__(self):
        acl = [
            ('WRITE', LogDelivery()),
            ('READ_ACP', LogDelivery()),
            ('FULL_CONTROL', Owner()),
        ]
        ACL.__init__(self, acl)


class LoggingStatus(object):
    """
    Logging configulation
    """
    def __init__(self, xml=None):
        self.target_bucket = None
        # TODO: check what happen if we don't set
        # this parameter in AWS S3
        self.target_prefix = ''
        self.target_grants = []
        if xml:
            self._from_xml(xml)

    def _from_xml(self, xml):
        try:
            status_elem = fromstring(xml, 'BucketLoggingStatus')
            logging_elem = status_elem.find('./LoggingEnabled')
            if logging_elem:
                target_bucket_elem = logging_elem.find('./TargetBucket')
                self.target_bucket = target_bucket_elem.text
                target_prefix_elem = logging_elem.find('./TargetPrefix')
                if target_prefix_elem is not None:
                    self.target_prefix = target_prefix_elem.text

                grants_elem = logging_elem.find('./TargetGrants')
                if grants_elem is not None:
                    for grant_elem in grants_elem.iterchildren('Grant'):
                        self.target_grants.append(parse_grant_elem(grant_elem))
        except Exception as e:
            print e  # FIXME: use logger
            raise MalformedXML()

    def to_xml(self):
        status_elem = Element('BucketLoggingStatus')
        if self.target_bucket:
            logging_elem = SubElement(status_elem, 'LoggingEnabled')

            SubElement(logging_elem, 'TargetBucket').text = self.target_bucket
            SubElement(logging_elem, 'TargetPrefix').text = self.target_prefix

            # TODO: check the case when there is no grant
            grants_elem = SubElement(logging_elem, 'TargetGrants')
            for permission, grantee in self.target_grants:
                grant_elem = SubElement(grants_elem, 'Grant')
                grantee.add_xml_element(grant_elem)
                SubElement(grant_elem, 'Permission').text = permission

        return tostring(status_elem)


class Expiration(object):
    def __init__(self, elem):
        self.days = None
        self.date = None
        self.from_xml(elem)

    def _iso8601_to_datetime(self, iso_date):
        fmt = '%Y-%m-%dT%H:%M:%S'
        if '.' in iso_date:
            fmt += '.%f'
        if iso_date[-1] == 'Z':
            fmt += 'Z'

        return datetime.strptime(iso_date, fmt)

    def from_xml(self, elem):
        if elem.find('./Days') is not None:
            self.days = int(elem.find('./Days').text)
        elif elem.find('./Date') is not None:
            try:
                iso_date = elem.find('./Date').text
                d = self._iso8601_to_datetime(iso_date)
            except Exception:
                raise MalformedXML()

            if d.hour or d.minute or d.second or d.microsecond:
                raise InvalidArgument('Date', d,
                                      'Date must be at midnight GMT')

            self.date = d
        else:
            raise MalformedXML()

    def to_xml(self, parent_elem):
        if self.days is not None:
            SubElement(parent_elem, 'Days').text = str(self.days)
        else:
            SubElement(parent_elem, 'Date').text = \
                self.date.isoformat() + '.000Z'

    def expire_time(self, creation_time):
        if self.days is not None:
            return float(creation_time) + self.days * 24 * 60 * 60
        else:
            return calendar.timegm(self.date.timetuple())


class Rule(object):
    def __init__(self, rule_elem):
        self.id = None
        self.prefix = ''
        self.enabled = True
        self.expiration = None
        self.from_xml(rule_elem)

    def from_xml(self, rule_elem):
        if rule_elem.find('./Transition'):
            raise NotImplemented("Transition is not supported")

        id_elem = rule_elem.find('./ID')
        if id_elem is None:
            self.id = utils.unique_id()
        else:
            self.id = id_elem.text

        prefix_elem = rule_elem.find('./Prefix')
        if prefix_elem is None:
            raise MalformedXML()
        self.prefix = prefix_elem.text or ''

        status_elem = rule_elem.find('./Status')
        if status_elem.text == 'Enabled':
            self.enabled = True
        elif status_elem.text == 'Disabled':
            self.enabled = False
        else:
            raise MalformedXML()

        expire_elem = rule_elem.find('./Expiration')
        if expire_elem is None:
            err_msg = 'At least one action needs to be specified in a rule.'
            raise InvalidArgument('Action', 'null', err_msg)
        self.expiration = Expiration(expire_elem)

    def to_xml(self, parent_elem):
        SubElement(parent_elem, 'ID').text = self.id
        SubElement(parent_elem, 'Prefix').text = self.prefix
        SubElement(parent_elem, 'Status').text = \
            'Enabled' if self.enabled else 'Disabled'
        expire_elem = SubElement(parent_elem, 'Expiration')
        self.expiration.to_xml(expire_elem)

    def to_header(self, object_name, creation_time):
        ts = self.expire_time(object_name, creation_time)
        if ts is None:
            return None
        expiry_date = time.strftime(
            "%a, %d %b %Y %H:%M:%S GMT", time.gmtime(ts))
        return 'expiry-date="%s", rule-id="%s"' % (expiry_date, self.id)

    def expire_time(self, object_name, creation_time):
        if not object_name.startswith(self.prefix):
            return None

        return self.expiration.expire_time(creation_time)


class LifecycleConf(object):
    """
    Lifecycle configulation
    """
    def __init__(self, xml=None, ts=None):
        if ts is None:
            ts = utils.normalized_currrent_timestamp()

        self.timestamp = ts
        self.rules = []
        if xml:
            self._from_xml(xml)

    def _add_rule(self, new_rule):
        if len(self.rules) >= utils.MAX_LIFECYCLE_RULES:
            raise MalformedXML()

        # validate new rule
        for rule in self.rules:
            if new_rule.id == rule.id:
                err_msg = 'RuleId must be unique. Found same ID for more' \
                    ' than one rule.'
                raise InvalidArgument('ID', rule.id, err_msg)

            if new_rule.prefix.startswith(rule.prefix) or \
                    rule.prefix.startswith(new_rule.prefix):
                err_msg = 'Found overlapping prefixes %s, %s' % \
                    (rule.prefix, new_rule.prefix)
                raise InvalidRequest(err_msg)

        self.rules.append(new_rule)

    def _from_xml(self, xml):
        try:
            conf_elem = fromstring(xml, 'LifecycleConfiguration')
            for rule_elem in conf_elem.iterchildren('Rule'):
                rule = Rule(rule_elem)
                self._add_rule(rule)

        except S3ErrorResponse:
            raise
        except Exception as e:
            print e  # FIXME: use logger
            raise MalformedXML()

    def to_xml(self):
        conf_elem = Element('LifecycleConfiguration')
        for rule in self.rules:
            rule_elem = SubElement(conf_elem, 'Rule')
            rule.to_xml(rule_elem)

        return tostring(conf_elem)

    def expire_time(self, obj_name, c_time):
        for rule in self.rules:
            utctime = rule.expire_time(obj_name, c_time)
            if utctime is not None and rule.enabled:
                return utctime
        return None

    def to_header(self, obj_name, c_time):
        for rule in self.rules:
            header = rule.to_header(obj_name, c_time)
            if header is not None:
                return header
        return None


class LifecycleConfHistory(list):
    """
    """
    def check_expiration(self, obj_name, c_time):
        confs = self
        confs_next = confs[1:]
        confs_next.append(None)
        for conf, conf_next in zip(confs, confs_next):
            if conf_next:
                if c_time > conf_next.timestamp:
                    continue
            expire = conf.expire_time(obj_name, c_time)
            if expire is None:
                continue
            end = float(conf_next.timestamp if conf_next else time.time())
            if expire <= end:
                return True
        return False
