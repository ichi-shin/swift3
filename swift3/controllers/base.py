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

import functools

from swift3.response import AccessDenied, NoSuchBucket, NoSuchVersion, \
    S3NotImplemented, InvalidRequest
from swift3.utils import unique_id, json_to_objects, camel_to_snake, LOGGER


def bucket_owner_required(func):
    """
    """
    @functools.wraps(func)
    def wrapped(self, req):
        bucket_info = req.get_bucket_info(self.app)
        if bucket_info['acl'].owner != req.user_id:
            raise AccessDenied()

        return func(self, req)

    return wrapped


def bucket_operation(func=None, err_resp=None, err_msg=None):
    """
    A decorator to ensure that the request is a bucket operation.  If the
    target resource is an object, this decorator updates the request by default
    so that the controller handles it as a bucket operation.  If 'err_resp' is
    specified, this raises it on error instead.
    """
    def _bucket_operation(func):
        @functools.wraps(func)
        def wrapped(self, req):
            if not req.is_bucket_request:
                if err_resp:
                    raise err_resp(msg=err_msg)

                LOGGER.debug('A key is specified for bucket API.')
                req.object_name = None

            return func(self, req)

        return wrapped

    if func:
        return _bucket_operation(func)
    else:
        return _bucket_operation


def object_operation(func):
    """
    A decorator to ensure that the request is an object operation.  If the
    target resource is not an object, this raises an error response.
    """
    @functools.wraps(func)
    def wrapped(self, req):
        if not req.is_object_request:
            raise InvalidRequest('A key must be specified')

        return func(self, req)

    return wrapped


class Controller(object):
    """
    Base WSGI controller class for the middleware
    """
    def __init__(self, app, **kwargs):
        self.app = app

    @classmethod
    def resource_type(cls):
        """
        Returns the target resource type of this controller.
        """
        name = cls.__name__[:-len('Controller')]
        return camel_to_snake(name).upper()

    def versions_iter(self, req, obj=None, prefix=None, key_marker=None,
                      version_id_marker=None):
        # if object name is not specified, iterates all the version objects
        if obj is None:
            query = {'format': 'json'}
            if prefix:
                query['prefix'] = prefix
            if key_marker:
                if version_id_marker:
                    # some of key_marker objects may be valid
                    query['marker'] = key_marker[:-1]
                else:
                    query['marker'] = key_marker

            resp = req.get_response(self.app, 'GET', obj='', query=query)
            objects = json_to_objects(resp.body)
            for o in objects:
                for info in self.versions_iter(req, o['name'], prefix,
                                               key_marker, version_id_marker):
                    yield info
            return

        if key_marker is None:
            after_marker = True
        else:
            if obj < key_marker or obj == key_marker and version_id_marker:
                # no items we should yield for this object
                return

            after_marker = (obj > key_marker)

        # get the latest object first
        info = req.get_object_info(self.app, obj=obj)
        info = info.copy()
        info['raw_container'] = req.container_name
        info['raw_object'] = obj
        info['object'] = obj
        if not info['version_id']:
            info['version_id'] = 'null'

        if after_marker:
            yield info
        elif info['version_id'] == version_id_marker:
            after_marker = True

        # iterate the versions container
        version_container = req.container_name + '+versions'
        query = {'format': 'json'}
        prefix_len = '%03x' % len(obj)
        query['prefix'] = prefix_len + obj + '/'

        try:
            resp = req.get_response(self.app, 'GET', version_container, '',
                                    query=query)
            for o in json_to_objects(resp.body)[::-1]:
                name, ts = o['name'][3:].rsplit('/', 1)

                info = req.get_object_info(self.app, version_container,
                                           o['name'])
                info = info.copy()
                info['raw_container'] = version_container
                info['raw_object'] = o['name']
                info['object'] = name
                info['ts'] = ts  # TODO: add explanation
                if not info['version_id']:
                    info['version_id'] = 'null'

                if after_marker:
                    yield info
                elif info['version_id'] == version_id_marker:
                    after_marker = True
        except NoSuchBucket:
            # probably, versioning is not enabled on this bucket
            pass

    def find_version_object(self, req, version_id):
        for info in self.versions_iter(req, req.object_name):
            if info['version_id'] == version_id:
                return info['raw_container'], info['raw_object']

        raise NoSuchVersion(req.object_name, version_id)

    def add_version_id(self, req):
        bucket_info = req.get_bucket_info(self.app)
        versioning = bucket_info['versioning']

        if versioning is None:
            pass
        elif versioning.status == 'Enabled':
            req.version_id = unique_id()
        elif versioning.status == 'Suspended':
            container, obj = self.find_version_object(req, 'null')
            if container == req.container_name:  # the latest object
                req.environ['swift_versioned_copy'] = True
            else:
                # remove previous object with null version id
                req.get_response(self.app, 'DELETE', container, obj)


class UnsupportedController(Controller):
    """
    Handles unsupported requests.
    """
    def __init__(self, app, **kwargs):
        raise S3NotImplemented('The requested resource is not implemented')
