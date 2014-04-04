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
import uuid
import base64
from datetime import datetime
import time
from simplejson import loads

from swift.common.swob import UTC
from swift.common.utils import normalize_timestamp, get_logger

from swift3.cfg import CONF

XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'
XMLNS_XSD = 'http://www.w3.org/2001/XMLSchema'

LOGGER = get_logger(CONF, log_route='swift3')


def sysmeta_prefix(resource):
    """
    Returns the system metadata prefix for given resource type.
    """
    if resource == 'object':
        # TODO: Return object-sysmeta-swift3 after Swift supports system
        # metadata for objects.

        # There is no worry that the user will use the same prefix for object
        # metadata.  S3 forbids including square brackets in the metadata name.
        return 'x-object-meta-[swift3]-'
    else:
        return 'x-container-sysmeta-swift3-'


def sysmeta_header(resource, name):
    """
    Returns the system metadata header for given resource type and name.
    """
    return sysmeta_prefix(resource) + name


def json_to_objects(json):
    objects = loads(json)
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


def valid_uri_name(name):
    if len(name) == 0:
        return True

    if max([ord(char) for char in name]) < 128:
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
