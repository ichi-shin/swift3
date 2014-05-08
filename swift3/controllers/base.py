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

from swift3.utils import camel_to_snake
from swift3.response import NotImplemented


class Controller(object):
    """
    Base WSGI controller class for the middleware
    """
    def __init__(self, app, logger, **kwargs):
        self.app = app
        self.logger = logger

    @classmethod
    def get_resource_type(cls):
        # resource name should be resoleved in log_deliver, and class name
        # should be based on subresource name instead of resource type name.

        name = cls.__name__[:-len('Controller')]
        return camel_to_snake(name).upper()


class UnsupportedController(Controller):
    """
    """
    def __init__(self, app, logger, **kwargs):
        raise NotImplemented('The requested resource is not implemented')
