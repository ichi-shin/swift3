# Copyright (c) 2010-2014 OpenStack Foundation.
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

from simplejson import loads

from swift.common.swob import HTTPOk

from swift3.response import NoSuchBucket, AccessDenied
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
        resp = req.get_swift_account(self.app, query={'format': 'json'})

        list_result_elem = Element('ListAllMyBucketsResult')
        owner_elem = SubElement(list_result_elem, 'Owner')
        SubElement(owner_elem, 'ID').text = req.user_id
        SubElement(owner_elem, 'DisplayName').text = req.user_id
        buckets_elem = SubElement(list_result_elem, 'Buckets')

        for container in loads(resp.body):
            c = container['name']

            if not valid_container_name(c):
                continue

            try:
                sub_resp = req.head_swift_container(self.app, container=c)
            except AccessDenied:
                continue
            except NoSuchBucket:
                continue

            if sub_resp.bucket_owner != req.user_id:
                # This is not my bucket
                continue

            date = format_timestamp(sub_resp.x_timestamp)

            bucket_elem = SubElement(buckets_elem, 'Bucket')
            SubElement(bucket_elem, 'Name').text = c
            SubElement(bucket_elem, 'CreationDate').text = date

        body = tostring(list_result_elem)

        return HTTPOk(content_type='application/xml', body=body)
