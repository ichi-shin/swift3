# Copyright (c) 2010-2014 OpenStack Foundation.
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

from simplejson import loads

from swift3.response import NoSuchBucket, AccessDenied, HTTPOk
from swift3.controllers.base import Controller
from swift3.utils import format_timestamp, valid_container_name
from swift3.etree import Element, SubElement, tostring


class ServiceController(Controller):
    """
    Handles account level requests.
    """
    def GET(self, req):
        """
        Handle GET Service request
        """
        resp = req.get_response(self.app, query={'format': 'json'})

        elem = Element('ListAllMyBucketsResult')

        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = req.user_id
        SubElement(owner, 'DisplayName').text = req.user_id

        buckets = SubElement(elem, 'Buckets')

        for container in loads(resp.body):
            c = container['name']

            if not valid_container_name(c):
                continue

            try:
                bucket_info = req.get_bucket_info(self.app, c)
            except AccessDenied:
                continue
            except NoSuchBucket:
                continue

            if bucket_info['acl'].owner != req.user_id:
                # This is not my bucket
                continue

            date = format_timestamp(bucket_info['ts'])

            bucket = SubElement(buckets, 'Bucket')
            SubElement(bucket, 'Name').text = c
            SubElement(bucket, 'CreationDate').text = date

        body = tostring(elem)

        return HTTPOk(content_type='application/xml', body=body)
