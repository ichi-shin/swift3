# Copyright (c) 2014 OpenStack Foundation.
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
from datetime import datetime
import time
import calendar
from functools import partial
from itertools import combinations, count
from simplejson import loads, dumps
from memoize import mproperty

from swift3.response import InvalidArgument, MalformedACLError, \
    MalformedXML, S3NotImplemented, InvalidRequest, \
    IllegalVersioningConfigurationException, AccessDenied, InternalError
from swift3.etree import Element, SubElement, fromstring, tostring, \
    XMLSyntaxError, DocumentInvalid
from swift3.utils import LOGGER, unique_id, sysmeta_header
from swift3.cfg import CONF
from swift3.exception import InvalidSubresource

XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'

UNDEFINED_OWNER_VALUE = 'undefined'


def encode_subresource(resource, name, value):
    """
    Encode an ACL instance to Swift metadata.

    Given a resource type and an ACL instance, this method returns HTTP
    headers, which can be used for Swift metadata.
    """
    value = dumps(value.encode(), separators=(',', ':'))
    n = CONF.max_meta_value_length
    segs = [value[i:i + n] for i in range(0, len(value), n)]
    segs.append('')  # add a terminater

    headers = {}
    for i, value in enumerate(segs):
        if i == 0:
            key = sysmeta_header(resource, name)
        else:
            key = sysmeta_header(resource, name) + '-' + str(i)
        headers[key] = value

    return headers


def decode_subresource(resource, name, headers):
    """
    Decode Swift metadata to an ACL instance.

    Given a resource type and HTTP headers, this method returns an ACL
    instance.
    """
    value = ''

    for i in count():
        if i == 0:
            key = sysmeta_header(resource, name)
        else:
            key = sysmeta_header(resource, name) + '-' + str(i)
        if key not in headers or not headers[key]:
            break
        value += headers[key]

    try:
        for cls in SubResource.__subclasses__():  # pylint: disable-msg=E1101
            if cls.metadata_name == name:
                if value == '':
                    return cls.default()

                return cls.decode(loads(value))
    except Exception as e:
        LOGGER.debug(e)
        pass

    raise InvalidSubresource((resource, name, value))


class SubResource(object):
    """
    Base class for S3 sub-resource
    """
    metadata_name = ''
    root_tag = 'unused'
    max_xml_length = 0

    def __init__(self, xml):
        try:
            self.elem = fromstring(xml, self.root_tag)
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except Exception as e:
            LOGGER.error(e)
            raise

        self.validate()

    def validate(self):
        pass

    @classmethod
    def default(cls):
        return None

    @mproperty
    def xml(self):
        """
        Returns an XML representation of this instance.
        """
        return tostring(self.elem)

    def encode(self):
        """
        Represent this instance with JSON serializable types.
        """
        return self.xml

    @classmethod
    def decode(cls, value):
        """
        Given an encoded object and return a corresponding subresource.
        """
        return cls(value)


class Grantee(object):
    """
    Base class for grantee.
    """
    def __contains__(self, key):
        """
        The key argument is a S3 user id.  This method checks that the user id
        belongs to this class.
        """
        raise S3NotImplemented()

    def encode(self):
        """
        Represent this instance with JSON serializable types.
        """
        raise S3NotImplemented()

    @classmethod
    def decode(cls, value):
        """
        Decode the value to an etree element.
        """
        raise S3NotImplemented()

    @mproperty
    def elem(self):
        """
        Get an etree element of this instance.
        """
        return self.decode(self.encode())

    @classmethod
    def from_header(cls, grantee):
        """
        Convert a grantee string in the HTTP header to an Grantee instance.
        """
        type, value = grantee.split('=', 1)
        value = value.strip('"\'')
        if type == 'id':
            return User(value)
        elif type == 'emailAddress':
            raise S3NotImplemented()
        elif type == 'uri':
            return Group.from_uri(value)
        else:
            raise InvalidArgument(type, value,
                                  'Argument format not recognized')


class User(Grantee):
    """
    Canonical user class for S3 accounts.
    """
    type = 'CanonicalUser'

    def __init__(self, name):
        self.id = name
        self.display_name = name

    def __contains__(self, key):
        return key == self.id

    def encode(self):
        return [self.id, self.display_name]

    @classmethod
    def decode(cls, value):
        elem = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        elem.set('{%s}type' % XMLNS_XSI, cls.type)
        SubElement(elem, 'ID').text = value[0]
        SubElement(elem, 'DisplayName').text = value[1]
        return elem

    def __str__(self):
        return self.display_name


def canned_acl_grant(bucket_owner, object_owner=None):
    """
    A set of predefined grants supported by AWS S3.
    """
    owner = object_owner or bucket_owner

    return {
        'private': [
            ('FULL_CONTROL', User(owner)),
        ],
        'public-read': [
            ('READ', AllUsers()),
            ('FULL_CONTROL', User(owner)),
        ],
        'public-read-write': [
            ('READ', AllUsers()),
            ('WRITE', AllUsers()),
            ('FULL_CONTROL', User(owner)),
        ],
        'authenticated-read': [
            ('READ', AuthenticatedUsers()),
            ('FULL_CONTROL', User(owner)),
        ],
        'bucket-owner-read': [
            ('READ', User(bucket_owner)),
            ('FULL_CONTROL', User(owner)),
        ],
        'bucket-owner-full-control': [
            ('FULL_CONTROL', User(owner)),
            ('FULL_CONTROL', User(bucket_owner)),
        ],
        'log-delivery-write': [
            ('WRITE', LogDelivery()),
            ('READ_ACP', LogDelivery()),
            ('FULL_CONTROL', User(owner)),
        ],
    }


class Group(Grantee):
    """
    Base class for Amazon S3 Predefined Groups
    """
    type = 'Group'
    uri = ''

    def encode(self):
        return self.__class__.__name__

    @classmethod
    def decode(cls, value):
        elem = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        elem.set('{%s}type' % XMLNS_XSI, cls.type)
        SubElement(elem, 'URI').text = cls.uri

        return elem

    @classmethod
    def from_uri(cls, uri):
        """
        Convert a URI to one of the predefined groups.
        """
        for group in Group.__subclasses__():  # pylint: disable-msg=E1101
            if group.uri == uri:
                return group()

        raise InvalidArgument('uri', uri, 'Invalid group uri')

    def __str__(self):
        name = re.sub('(.)([A-Z])', r'\1 \2', self.__class__.__name__)
        return name + ' group'


class AuthenticatedUsers(Group):
    """
    This group represents all AWS accounts.  Access permission to this group
    allows any AWS account to access the resource.  However, all requests must
    be signed (authenticated).
    """
    uri = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'

    def __contains__(self, key):
        # Swift3 handles only signed requests.
        return True


class AllUsers(Group):
    """
    Access permission to this group allows anyone to access the resource.  The
    requests can be signed (authenticated) or unsigned (anonymous).  Unsigned
    requests omit the Authentication header in the request.

    Note: Swift3 regards unsigned requests as Swift API accesses, and bypasses
    them to Swift.  As a result, AllUsers behaves completely same as
    AuthenticatedUsers.
    """
    uri = 'http://acs.amazonaws.com/groups/global/AllUsers'

    def __contains__(self, key):
        return True


class LogDelivery(Group):
    """
    WRITE and READ_ACP permissions on a bucket enables this group to write
    server access logs to the bucket.
    """
    uri = 'http://acs.amazonaws.com/groups/s3/LogDelivery'

    def __contains__(self, key):
        if ':' in key:
            tenant, user = key.split(':', 1)
        else:
            user = key
        return user == CONF.log_delivery_user


class Grant(object):
    def __init__(self, elem):
        self.elem = elem

    def validate(self):
        e = self.elem.find('./Grantee')
        type = e.get('{%s}type' % XMLNS_XSI)

        if type == 'Group':
            # Confirm that the specified URI is valid.
            Group.from_uri(e.find('./URI').text)
        elif type == 'AmazonCustomerByEmail':
            raise S3NotImplemented()

    def encode(self):
        """
        Represent this instance with JSON serializable types.
        """
        return [self.permission, self.grantee.encode()]

    @classmethod
    def decode(cls, value):
        """
        Decode the value to an etree element.
        """
        permission, grantee = value
        elem = Element('Grant')
        grantee_elem = None

        if isinstance(grantee, list):
            grantee_elem = User.decode(grantee)
        else:
            for group in Group.__subclasses__():  # pylint: disable-msg=E1101
                if group.__name__ == grantee:
                    grantee_elem = group.decode(grantee)
                    break

        if grantee_elem is None:
            raise InternalError(grantee)

        elem.append(grantee_elem)
        SubElement(elem, 'Permission').text = permission

        return elem

    @mproperty
    def permission(self):
        return self.elem.find('./Permission').text

    @mproperty
    def grantee(self):
        e = self.elem.find('./Grantee')
        type = e.get('{%s}type' % XMLNS_XSI)

        if type == Group.type:
            return Group.from_uri(e.find('./URI').text)
        elif type == User.type:
            return User(e.find('./ID').text)
        else:
            raise S3NotImplemented()

    def __iter__(self):
        yield self.permission
        yield self.grantee

    def allow(self, grantee, permission):
        if not CONF.allow_public_write:
            if self.permission == 'WRITE' and \
                    isinstance(self.grantee, AllUsers):
                # public write is not allowed
                return False

        return permission == self.permission and grantee in self.grantee


class ACL(SubResource):
    """
    S3 ACL class.
    """
    metadata_name = 'acl'
    root_tag = 'AccessControlPolicy'
    max_xml_length = 200 * 1024

    def __init__(self, xml):
        try:
            SubResource.__init__(self, xml)
        except MalformedXML:
            raise MalformedACLError()

    def validate(self):
        if len(self.grant) > CONF.max_acl_grants:
            raise MalformedACLError()
        for g in self.grant:
            g.validate()

    @classmethod
    def default(cls):
        return cls.from_grant([], UNDEFINED_OWNER_VALUE)

    def encode(self):
        """
        Represent this instance with JSON serializable types.
        """
        return [self.owner] + [g.encode() for g in self.grant]

    @classmethod
    def decode(cls, value):
        """
        Decode the value to an ACL instance.
        """
        elem = Element(cls.root_tag)

        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = value[0]
        SubElement(owner, 'DisplayName').text = value[0]

        SubElement(elem, 'AccessControlList').extend(
            Grant.decode(g) for g in value[1:]
        )

        return cls(tostring(elem))

    @mproperty
    def owner(self):
        return self.elem.find('./Owner/ID').text

    @mproperty
    def grant(self):
        return [Grant(e) for e in
                self.elem.findall('./AccessControlList/Grant')]

    def check_owner(self, user_id):
        """
        Check that the user is an owner.
        """
        if not CONF.s3_acl:
            # Ignore Swift3 ACL.
            return

        if self.owner == UNDEFINED_OWNER_VALUE:
            if CONF.allow_no_owner:
                # No owner means public.
                return

            raise AccessDenied()

        if user_id != self.owner:
            raise AccessDenied()

    def check_permission(self, user_id, permission):
        """
        Check that the user has a permission.
        """
        if not CONF.s3_acl:
            # Ignore Swift3 ACL.
            return

        try:
            self.check_owner(user_id)

            # owners have full control permission
            return
        except AccessDenied:
            pass

        for g in self.grant:
            if g.allow(user_id, 'FULL_CONTROL') or \
                    g.allow(user_id, permission):
                return

        raise AccessDenied()

    @classmethod
    def from_headers(cls, headers, bucket_owner, object_owner=None):
        """
        Convert HTTP headers to an ACL instance.
        """
        grant = []
        try:
            for key, value in headers.items():
                if key.lower().startswith('x-amz-grant-'):
                    permission = key[len('x-amz-grant-'):]
                    permission = permission.upper().replace('-', '_')
                    for grantee in value.split(','):
                        grant.append((permission,
                                      Grantee.from_header(grantee)))

            if 'x-amz-acl' in headers:
                acl = headers['x-amz-acl']
                if len(grant) > 0:
                    err_msg = 'Specifying both Canned ACLs and Header ' \
                        'Grants is not allowed'
                    raise InvalidRequest(err_msg)

                if not CONF.allow_public_write and \
                        headers['x-amz-acl'] == 'public-read-write':
                    raise InvalidArgument('x-amz-acl', acl,
                                          'Public write is not allowed.')

                grant = canned_acl_grant(bucket_owner, object_owner)[acl]
        except (KeyError, ValueError):
            raise InvalidRequest()

        if len(grant) == 0:
            # No ACL headers
            return None

        return cls.from_grant(grant, bucket_owner, object_owner)

    @classmethod
    def from_grant(cls, grant, bucket_owner, object_owner=None):
        """
        Create an ACL instance based on the requested grant.
        """
        owner = object_owner or bucket_owner

        acp_elem = Element('AccessControlPolicy')
        owner_elem = SubElement(acp_elem, 'Owner')
        SubElement(owner_elem, 'ID').text = owner
        SubElement(owner_elem, 'DisplayName').text = owner

        acl_elem = SubElement(acp_elem, 'AccessControlList')
        for permission, grantee in grant:
            grant_elem = SubElement(acl_elem, 'Grant')
            grant_elem.append(grantee.elem)
            SubElement(grant_elem, 'Permission').text = permission

        return ACL(tostring(acp_elem))


class CannedACL(object):
    """
    A dict-like object that returns canned ACL.
    """
    def __getitem__(self, key):
        def acl(key, bucket_owner, object_owner=None):
            grant = canned_acl_grant(bucket_owner, object_owner)[key]

            return ACL.from_grant(grant, bucket_owner, object_owner)

        return partial(acl, key)

canned_acl = CannedACL()

ACLPrivate = canned_acl['private']
ACLPublicRead = canned_acl['public-read']
ACLPublicReadWrite = canned_acl['public-read-write']
ACLAuthenticatedRead = canned_acl['authenticated-read']
ACLBucketOwnerRead = canned_acl['bucket-owner-read']
ACLBucketOwnerFullControl = canned_acl['bucket-owner-full-control']
ACLLogDeliveryWrite = canned_acl['log-delivery-write']


class LoggingStatus(SubResource):
    """
    Logging configulation
    """
    metadata_name = 'logging'
    root_tag = 'BucketLoggingStatus'
    max_xml_length = 10 * 1024

    def encode(self):
        if self.enabled:
            return [self.target_bucket, self.target_prefix] + \
                [g.encode() for g in self.target_grant]
        else:
            return None

    @classmethod
    def decode(cls, value):
        elem = Element(cls.root_tag)
        if isinstance(value, list):
            e = SubElement(elem, 'LoggingEnabled')
            SubElement(e, 'TargetBucket').text = value[0]
            SubElement(e, 'TargetPrefix').text = value[1]

            if value[2:]:
                SubElement(e, 'TargetGrants').extend(
                    Grant.decode(g) for g in value[2:]
                )

        return cls(tostring(elem))

    @mproperty
    def enabled(self):
        e = self.elem.find('./LoggingEnabled')
        if e is None:
            return False

        return True

    @mproperty
    def target_bucket(self):
        e = self.elem.find('./LoggingEnabled/TargetBucket')
        if e is None:
            return None

        return e.text

    @mproperty
    def target_prefix(self):
        e = self.elem.find('./LoggingEnabled/TargetPrefix')
        if e is None:
            return None

        return e.text or ''

    @mproperty
    def target_grant(self):
        return [Grant(e) for e in
                self.elem.findall('./LoggingEnabled/TargetGrants/Grant')]


class Expiration(object):
    def __init__(self, elem):
        self.elem = elem

    def validate(self):
        d = self.date
        if d is None:
            return

        if d.hour or d.minute or d.second or d.microsecond:
            raise InvalidArgument('Date', d,
                                  'Date must be at midnight GMT')

    def encode(self):
        if self.days is not None:
            return self.days
        else:
            return self.date.strftime('%Y-%m-%d')

    @classmethod
    def decode(cls, value):
        if isinstance(value, int):
            elem = Element('Days')
            elem.text = str(value)
        else:
            elem = Element('Date')
            elem.text = value + 'T00:00:00.000Z'

        return elem

    @mproperty
    def days(self):
        e = self.elem.find('./Days')
        if e is None:
            return None

        return int(e.text)

    @mproperty
    def date(self):
        e = self.elem.find('./Date')
        if e is None:
            return None

        return self._iso8601_to_datetime(e.text)

    def _iso8601_to_datetime(self, iso_date):
        fmt = '%Y-%m-%dT%H:%M:%S'
        if '.' in iso_date:
            fmt += '.%f'
        if iso_date[-1] == 'Z':
            fmt += 'Z'

        return datetime.strptime(iso_date, fmt)

    def expire_time(self, creation_time):
        if self.days is not None:
            return float(creation_time) + self.days * 24 * 60 * 60
        else:
            return calendar.timegm(self.date.timetuple())


class Rule(object):
    def __init__(self, elem):
        self.elem = elem

    def validate(self):
        if self.elem.find('./Transition') is not None:
            raise S3NotImplemented("Transition is not supported")

        if self.elem.find('./Expiration') is None:
            err_msg = 'At least one action needs to be specified in a rule.'
            raise InvalidArgument('Action', 'null', err_msg)

        self.expiration.validate()

    def encode(self):
        return [self.id, self.prefix, 1 if self.enabled else 0, '',
                self.expiration.encode()]

    @classmethod
    def decode(cls, value):
        id, prefix, enabled, _, expiration = value
        elem = Element('Rule')
        SubElement(elem, 'ID').text = id
        SubElement(elem, 'Prefix').text = prefix
        SubElement(elem, 'Status').text = 'Enabled' if enabled else 'Disabled'
        SubElement(elem, 'Expiration').append(Expiration.decode(expiration))

        return elem

    @mproperty
    def id(self):
        id_elem = self.elem.find('./ID')
        if id_elem is None:
            id_elem = Element('ID')
            id_elem.text = unique_id()
            self.elem[0].addprevious(id_elem)

        return id_elem.text or ''

    @mproperty
    def prefix(self):
        return self.elem.find('./Prefix').text or ''

    @mproperty
    def enabled(self):
        status_elem = self.elem.find('./Status')
        if status_elem.text == 'Enabled':
            return True

        return False

    @mproperty
    def expiration(self):
        return Expiration(self.elem.find('./Expiration'))

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


class Lifecycle(SubResource):
    """
    Lifecycle configulation
    """
    metadata_name = 'lifecycle'
    root_tag = 'LifecycleConfiguration'
    max_xml_length = 153934

    def validate(self):
        if len(self.rules) > CONF.max_lifecycle_rules:
            raise MalformedXML()

        for rule in self.rules:
            rule.validate()

        for a, b in combinations(self.rules, 2):
            if a.id == b.id:
                err_msg = 'RuleId must be unique. Found same ID for more' \
                    ' than one rule.'
                raise InvalidArgument('ID', a.id, err_msg)

            if a.prefix.startswith(b.prefix) or b.prefix.startswith(a.prefix):
                err_msg = 'Found overlapping prefixes %s, %s' % \
                    (a.prefix, b.prefix)
                raise InvalidRequest(err_msg)

    def encode(self):
        return [r.encode() for r in self.rules]

    @classmethod
    def decode(cls, value):
        elem = Element(cls.root_tag)
        for rule in value:
            elem.append(Rule.decode(rule))

        return cls(tostring(elem))

    @mproperty
    def rules(self):
        _rules = []
        for e in self.elem.iterchildren('Rule'):
            _rules.append(Rule(e))

        return _rules

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

    def check_expiration(self, obj_name, c_time):
        expire = self.expire_time(obj_name, c_time)
        if expire and expire <= time.time():
                return True
        return False


class Versioning(SubResource):
    """
    Versioning configuration.
    """
    metadata_name = 'versioning'
    root_tag = 'VersioningConfiguration'
    max_xml_length = 1024

    def validate(self):
        if self.status is None:
            msg = 'The Versioning element must be specified'
            raise IllegalVersioningConfigurationException(msg)

    def encode(self):
        return self.status

    @classmethod
    def decode(cls, value):
        elem = Element(cls.root_tag)
        SubElement(elem, 'Status').text = value

        return cls(tostring(elem))

    @mproperty
    def status(self):
        e = self.elem.find('./Status')
        if e is None:
            return None

        return e.text
