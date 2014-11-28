#!/usr/bin/env python
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

import sys

from swift3.etree import fromstring, tostring
from swift3.cfg import CONF

if __name__ == '__main__':
    CONF.pretty_print_xml = True
    xml = sys.stdin.read().replace('\n', '')
    elem = fromstring(xml)
    print tostring(elem, use_s3ns=False),
