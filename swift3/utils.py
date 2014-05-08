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
import uuid
import base64
from datetime import datetime
import time
import simplejson

from swift.common.swob import UTC
from swift.common.utils import config_true_value, normalize_timestamp
from swift.common.middleware.acl import parse_acl, referrer_allowed

ALLOW_CONTAINER_PUBLIC_WRITE = True
DEFAULT_MAX_PARTS = 1000
DEFAULT_MAX_UPLOADS = 1000
DEFAULT_MAX_BUCKET_LISTING = 1000
PRETTY_PRINT_XML = False
LOG_DELIVERY_USER = '.log_delivery'
LOCATION = 'US'
MAX_ACL_GRANTS = 100
MAX_LIFECYCLE_RULES = 1000
MAX_MAX_BUCKET_LISTING = 2147483647
MAX_MAX_PARTS = 10000
MAX_MULTI_DELETE_OBJECTS = 1000
STORAGE_DOMAIN = None


def json_to_objects(json):
    objects = simplejson.loads(json)
    for o in objects:
        if 'subdir' in o:
            o['subdir'] = utf8encode(o['subdir'])
        if 'name' in o:
            o['name'] = utf8encode(o['name'])

    return objects


def utf8encode(s):
    if isinstance(s, unicode):
        s = s.encode('utf8')
    return s


def utf8decode(s):
    if isinstance(s, str):
        s = s.decode('utf8')
    return s


def valid_header_name(name):
    if re.search('[^!#$%&(*+-.0-9a-zA-Z^_|~`]', name) is None:
        return True

    return False


def valid_container_name(name):
    if re.search('[^0-9a-zA-Z-_.]', name) is None:
        return True

    return False


def normalized_currrent_timestamp():
    return normalize_timestamp(time.time())


def format_timestamp(ts):
    s = datetime.fromtimestamp(float(ts), UTC).isoformat()

    # Remove timezone info
    if re.search('\+[0-9][0-9]:[0-9][0-9]$', s):
        s = s[:-6]

    if re.search('\.[0-9]{6}$', s):
        return s[:-7] + '.000Z'
    else:
        # microsecond is 0
        return s + '.000Z'


def get_owner_from_acl(headers):
    write_acl = headers.get('x-container-write')
    read_acl = headers.get('x-container-read')
    _, write_grantees = parse_acl(write_acl)
    referrers, read_grantees = parse_acl(read_acl)
    for user in write_grantees:
        if user in read_grantees or \
                referrer_allowed('unknown', referrers):
            return user
    return 'undefined'


def update_swift3_conf(conf):
    global ALLOW_CONTAINER_PUBLIC_WRITE
    ALLOW_CONTAINER_PUBLIC_WRITE = config_true_value(
        conf.get('allow_container_public_write', ALLOW_CONTAINER_PUBLIC_WRITE))

    global DEFAULT_MAX_BUCKET_LISTING
    DEFAULT_MAX_BUCKET_LISTING = conf.get('default_max_bucket_listing',
                                          DEFAULT_MAX_BUCKET_LISTING)

    global DEFAULT_MAX_PARTS
    DEFAULT_MAX_PARTS = conf.get('default_max_parts', DEFAULT_MAX_PARTS)

    global DEFAULT_MAX_UPLOADS
    DEFAULT_MAX_UPLOADS = conf.get('default_max_uploads', DEFAULT_MAX_UPLOADS)

    global PRETTY_PRINT_XML
    PRETTY_PRINT_XML = config_true_value(
        conf.get('pretty_print_xml', PRETTY_PRINT_XML))

    global LOG_DELIVERY_USER
    LOG_DELIVERY_USER = conf.get('log_delivery_user', LOG_DELIVERY_USER)

    global LOCATION
    LOCATION = conf.get('location', LOCATION)

    global MAX_ACL_GRANTS
    MAX_ACL_GRANTS = conf.get('max_acl_grants', MAX_ACL_GRANTS)

    global MAX_MAX_BUCKET_LISTING
    MAX_MAX_BUCKET_LISTING = conf.get('max_max_bucket_listing',
                                      MAX_MAX_BUCKET_LISTING)

    global MAX_LIFECYCLE_RULES
    MAX_LIFECYCLE_RULES = conf.get('max_lifecycle_rules', MAX_LIFECYCLE_RULES)

    global MAX_MAX_PARTS
    MAX_MAX_PARTS = conf.get('max_max_parts', MAX_MAX_PARTS)

    global MAX_MULTI_DELETE_OBJECTS
    MAX_MULTI_DELETE_OBJECTS = conf.get('max_multi_delete_objects',
                                        MAX_MULTI_DELETE_OBJECTS)

    global STORAGE_DOMAIN
    STORAGE_DOMAIN = conf.get('storage_domain')


# (camel, snake)
_reserved_names = [
    ('ID', 'id'),
    ('URI', 'uri'),
]


def camel_to_snake(camel):
    for c, s in _reserved_names:
        if c == camel:
            return s

    return re.sub('(.)([A-Z])', r'\1_\2', camel).lower()


def snake_to_camel(snake):
    for c, s in _reserved_names:
        if s == snake:
            return c

    return snake.title().replace('_', '')


def unique_id():
    return base64.urlsafe_b64encode(str(uuid.uuid4()))
