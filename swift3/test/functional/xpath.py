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

from swift3.etree import fromstring

if __name__ == '__main__':
    xml = sys.stdin.read()
    xpath = sys.argv[1]
    elem = fromstring(xml)
    result = elem.xpath(xpath)
    if not result:
        err_msg = 'Element not found\n'
        err_msg += 'xpath = %s\n' % xpath
        err_msg += 'xml = %s' % xml
        sys.exit(err_msg)
    print result[0]
