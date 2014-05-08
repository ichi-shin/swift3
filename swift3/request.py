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

import md5
from urllib import quote, unquote
import base64
import email.utils
import datetime
from swift3.etree import Element, SubElement, fromstring, tostring

from swift.common.utils import normalize_timestamp
from swift.common.utils import split_path
from swift.common.swob import Request, HeaderKeyDict, HeaderEnvironProxy
from swift.common.http import HTTP_OK, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, \
    HTTP_SERVICE_UNAVAILABLE, HTTP_NO_CONTENT, HTTP_NOT_FOUND, HTTP_ACCEPTED, \
    HTTP_CREATED, HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, \
    HTTP_REQUEST_ENTITY_TOO_LARGE, HTTP_PARTIAL_CONTENT, \
    HTTP_LENGTH_REQUIRED, HTTP_PRECONDITION_FAILED, HTTP_NOT_MODIFIED, \
    HTTP_REQUESTED_RANGE_NOT_SATISFIABLE
from swift.common.constraints import check_utf8

from swift3.response import AccessDenied, ServiceUnavailable, InternalError, \
    NoSuchBucket, BucketAlreadyExists, BucketNotEmpty, NoSuchKey, \
    InvalidDigest, EntityTooLarge, InvalidArgument, \
    RequestTimeTooSkewed, S3Response, SignatureDoesNotMatch, \
    MissingContentLength, NoSuchVersion, NoSuchLifecycleConfiguration, \
    NoSuchUpload, PreconditionFailed, InvalidRange, InvalidRequest, \
    MalformedXML, InvalidBucketState, InvalidURI, InvalidBucketName, \
    InvalidStorageClass, NotImplemented, InvalidTargetBucketForLogging, \
    IllegalVersioningConfigurationException, MethodNotAllowed
from swift3.exception import NotS3Request
from swift3.controllers import ServiceController, BucketController, \
    ObjectController, AclController, MultiObjectDeleteController, \
    UploadController, LocationController, LoggingStatusController, \
    VersioningController, LifecycleController, PartController, \
    UploadsController, BucketversionsController, UnsupportedController
from swift3 import utils
from swift3.acl import ACL, ACLPrivate, LoggingStatus, \
    LifecycleConf, LifecycleConfHistory, Owner, AllUsers


# List of sub-resources that must be maintained as part of the HMAC
# signature string.
ALLOWED_SUB_RESOURCES = sorted([
    'acl', 'delete', 'lifecycle', 'location', 'logging', 'notification',
    'partNumber', 'policy', 'requestPayment', 'torrent', 'uploads', 'uploadId',
    'versionId', 'versioning', 'versions', 'website',
    'response-cache-control', 'response-content-disposition',
    'response-content-encoding', 'response-content-language',
    'response-content-type', 'response-expires', 'cors', 'tagging', 'restore'
])

# List of sub-resources that be used as PUT request.
PUT_USED_SUB_RESOURCES = sorted([
    'acl', 'lifecycle', 'logging', 'notification', 'partNumber',
    'policy', 'requestPayment', 'uploadId', 'versionId', 'versioning',
    'versions', 'website', 'cors', 'tagging'
])


class VersionId(object):
    def __init__(self, ts, versioning_enabled=True):
        self.ts = normalize_timestamp(ts)
        if versioning_enabled:
            s = '%s/%s' % (md5.new(self.ts).digest(), self.ts)
            self.version_id = base64.urlsafe_b64encode(s).rstrip('=')
        else:
            self.version_id = 'null'

    @classmethod
    def parse(cls, version_id):
        try:
            s = version_id
            s += '=' * (-len(version_id) % 4)  # add padding
            s = base64.urlsafe_b64decode(s)
            ts_md5, ts = s.rsplit('/', 1)
            if ts_md5 != md5.new(ts).digest():
                raise InvalidArgument('versionId', version_id,
                                      "Invalid version id specified")
            return VersionId(ts)
        except Exception:
            raise InvalidArgument('versionId', version_id,
                                  "Invalid version id specified")

    def __cmp__(self, other):
        if isinstance(other, str):
            other = VersionId.parse(other)
        return -cmp(self.ts, other.ts)

    def __str__(self):
        return self.version_id


def _req_swift3_property(resource, name):
    key = 'x-%s-meta-[swift3]-%s' % (resource, name)

    def getter(self):
        return self.headers.get(key)

    def setter(self, value):
        self.headers[key] = value

    return property(getter, setter,
                    doc='Get and set the %s %s property' % (resource, name))


class S3Request(Request):
    bucket_owner = _req_swift3_property('container', 'owner')
    bucket_timestamp = _req_swift3_property('container', 'timestamp')
    object_owner = _req_swift3_property('object', 'owner')
    object_timestamp = _req_swift3_property('object', 'timestamp')
    versioned = _req_swift3_property('object', 'versioned')
    versioning_status = _req_swift3_property('container', 'versioning-status')
    delete_marker = _req_swift3_property('object', 'delete-marker')
    missing_meta = _req_swift3_property('object', 'missing-meta')

    def __init__(self, env):
        Request.__init__(self, env)

        self.access_key, self.signature = self._parse_authorization()
        self.bucket_in_host = self._parse_host()
        self.container_name, self.object_name = self._parse_uri()
        if self.container_name is not None and \
                not utils.valid_container_name(self.container_name):
            if self.method == 'PUT' and \
               not self._exists_put_used_sub_resources() and \
               self.copy_source is None:
                raise InvalidBucketName(self.container_name)
            else:
                raise NoSuchBucket(self.container_name)

        self._validate_headers()
        self.token = base64.urlsafe_b64encode(self._canonical_string())
        self.tenant_name = None
        self.keystone_token = None
        self.user_id = None
        self.object_size = None

    def _parse_host(self):
        storage_domain = utils.STORAGE_DOMAIN
        if not storage_domain:
            return None

        if storage_domain[0] != '.':
            storage_domain = '.' + storage_domain

        if 'HTTP_HOST' in self.environ:
            given_domain = self.environ['HTTP_HOST']
        elif 'SERVER_NAME' in self.environ:
            given_domain = self.environ['SERVER_NAME']
        else:
            return None

        port = ''
        if ':' in given_domain:
            given_domain, port = given_domain.rsplit(':', 1)
        if given_domain.endswith(storage_domain):
            return given_domain[:-len(storage_domain)]

        return None

    def _parse_uri(self):
        if not check_utf8(self.environ['PATH_INFO']):
            raise InvalidURI(self.path)

        if self.bucket_in_host:
            return unquote(self.bucket_in_host), self.environ['PATH_INFO'][1:]

        return self.split_path(0, 2, True)

    def _parse_authorization(self):
        if 'AWSAccessKeyId' in self.params:
            try:
                self.headers['Date'] = self.params['Expires']
                self.headers['Authorization'] = \
                    'AWS %(AWSAccessKeyId)s:%(Signature)s' % self.params
            except KeyError:
                raise AccessDenied()

        if 'Authorization' not in self.headers:
            raise NotS3Request

        try:
            keyword, info = self.headers['Authorization'].split(' ')
        except Exception:
            err_msg = "Authorization header is invalid -- " \
                "one and only one ' ' (space) required"
            raise InvalidArgument('Authorization',
                                  self.headers['Authorization'], err_msg)

        if keyword != 'AWS':
            raise InvalidArgument('Authorization',
                                  self.headers['Authorization'],
                                  'Unsupported Authorization Type')

        try:
            access_key, signature = info.rsplit(':', 1)
        except Exception:
            err_msg = 'AWS authorization header is invalid.  ' \
                'Expected AwsAccessKeyId:signature'
            raise InvalidArgument('Authorization',
                                  self.headers['Authorization'], err_msg)

        return access_key, signature

    def _validate_headers(self):
        if 'CONTENT_LENGTH' in self.environ:
            try:
                if self.content_length < 0:
                    raise InvalidRequest()
            except (ValueError, TypeError):
                raise InvalidRequest()

        if 'Date' in self.headers:
            now = datetime.datetime.utcnow()
            date = email.utils.parsedate(self.headers['Date'])
            if 'Expires' in self.params:
                try:
                    d = email.utils.formatdate(float(self.params['Expires']))
                except ValueError:
                    raise AccessDenied()
                expdate = email.utils.parsedate(d)

                date = datetime.datetime.utcnow().timetuple()

                # check expiration
                ex = datetime.datetime(*expdate[0:6])
                if now > ex:
                    raise AccessDenied('Request has expired')
            elif date is not None:
                epoch = datetime.datetime(1970, 1, 1, 0, 0, 0, 0)

                d1 = datetime.datetime(*date[0:6])
                if d1 < epoch:
                    raise AccessDenied()

                # If the standard date is too far ahead or behind, it is an
                # error
                delta = datetime.timedelta(seconds=60 * 5)
                if abs(d1 - now) > delta:
                    raise RequestTimeTooSkewed()
            else:
                raise AccessDenied()

        if 'Content-MD5' in self.headers:
            value = self.headers['Content-MD5']
            if value == '':
                raise InvalidDigest()
            try:
                self.headers['ETag'] = value.decode('base64').encode('hex')
            except Exception:
                raise InvalidDigest()
            if self.headers['ETag'] == '':
                raise AccessDenied()

        if 'x-amz-metadata-directive' in self.headers:
            value = self.headers['x-amz-metadata-directive']
            if value not in ('COPY', 'REPLACE'):
                err_msg = 'Unknown metadata directive.'
                raise InvalidArgument('x-amz-metadata-directive', value,
                                      err_msg)

        if 'x-amz-storage-class' in self.headers:
            if self.headers['x-amz-storage-class'] != 'STANDARD':
                raise InvalidStorageClass()

        if 'x-amz-mfa' in self.headers:
            raise NotImplemented('MFA Delete is not supported.')

        if 'x-amz-server-side-encryption' in self.headers:

            raise NotImplemented('Server-side encryption is not supported.')
        if 'x-amz-website-redirect-location' in self.headers:
            raise NotImplemented('Website redirection is not supported.')

    def get_basic_info(self, app):
        if self.container_name:
            path = '/v1/%s/%s' % (self.access_key, self.container_name)
        else:
            path = '/v1/%s' % self.access_key

        sw_req = self.make_swift_req(method='HEAD', path=path, body='')
        sw_resp = sw_req.get_response(app)
        if not sw_req.remote_user:
            raise SignatureDoesNotMatch()

        _, self.tenant_name, _ = split_path(sw_resp.environ['PATH_INFO'],
                                            2, 3, True)
        self.tenant_name = utils.utf8encode(self.tenant_name)

        if 'HTTP_X_USER_NAME' in sw_resp.environ:
            # keystone
            self.user_id = "%s:%s" % (sw_resp.environ['HTTP_X_TENANT_NAME'],
                                      sw_resp.environ['HTTP_X_USER_NAME'])
            self.user_id = utils.utf8encode(self.user_id)
            self.keystone_token = sw_req.environ['HTTP_X_AUTH_TOKEN']
        else:
            # tempauth
            self.user_id = self.access_key

        if self.container_name:
            bucket_owner = utils.get_owner_from_acl(sw_resp.headers)
            container_ts = \
                sw_resp.headers.get('x-container-meta-[swift3]-timestamp',
                                    None)
        else:
            bucket_owner = 'undefined'
            container_ts = None

        return self.tenant_name, self.user_id, bucket_owner, container_ts

    @property
    def copy_source(self):
        source = self.headers.get('x-amz-copy-source')
        if source is not None:
            source = unquote(source)

        return source

    @property
    def copy_source_version_id(self):
        return self.headers.get('x-amz-copy-source-version-id')

    @property
    def copy_source_environ(self):
        env = {}
        for key, value in self.environ.items():
            if key == 'HTTP_X_AMZ_COPY_SOURCE_VERSION_ID':
                continue
            elif key.startswith('HTTP_X_AMZ_COPY_SOURCE_'):
                env[key.replace('X_AMZ_COPY_SOURCE_', '')] = value

        return env

    @property
    def metadata_directive(self):
        return self.headers.get('x-amz-metadata-directive', 'COPY')

    def check_md5(self):
        if 'HTTP_CONTENT_MD5' not in self.environ:
            raise InvalidRequest('Missing required header for this request: '
                                 'Content-MD5')

        digest = md5.new(self.body).digest().encode('base64')[:-1]
        if self.environ['HTTP_CONTENT_MD5'] != digest:
            raise InvalidDigest(content_md5=self.environ['HTTP_CONTENT_MD5'])

    def check_bucket_owner(self, app):
        owner = self.get_bucket_owner(app)
        if not self.user_id == owner:
            raise AccessDenied()

    def get_container_ts(self, app, container=None):
        container = container or self.container_name
        if '+' in container:
            container = container.split('+')[0]

        resp = self.head_swift_container(app, container=container)
        container_ts = resp.bucket_timestamp

        # Create a swift3 timestamp for buckets created by Swift API
        if not container_ts:
            self.bucket_timestamp = resp.x_timestamp
            self.post_swift_container(app, container=container)
            container_ts = self.bucket_timestamp

        return container_ts

    def get_object_ts(self, app):
        resp = self.head_swift_object(app)
        object_ts = resp.object_timestamp

        # Create a swift3 timestamp for objects created by Swift API
        if not object_ts:
            self.object_timestamp = resp.x_timestamp
            # To keep the existing object-meta-data, we cannot use a post
            # request here.
            headers = {
                'content-length': 0,
                'x-copy-from': '/%s/%s' % (self.container_name,
                                           self.object_name),
            }
            self.put_swift_object(app, headers=headers)
            object_ts = self.object_timestamp

        return object_ts

    def get_object_version_id(self, app):
        version_id = ''
        resp = self.head_swift_object(app)
        versioned = resp.versioned

        if versioned:
            version_id = str(VersionId(self.get_object_ts(app)))

        return version_id

    def _canonical_uri(self):
        raw_path_info = self.environ.get('RAW_PATH_INFO', self.path)
        if self.bucket_in_host:
            raw_path_info = '/' + self.bucket_in_host + raw_path_info
        return raw_path_info

    def _canonical_string(self):
        """
        Canonicalize a request to a token that can be signed.
        """
        amz_headers = {}

        buf = "%s\n%s\n%s\n" % (self.method,
                                self.headers.get('Content-MD5', ''),
                                self.headers.get('Content-Type') or '')

        for amz_header in sorted((key.lower() for key in self.headers
                                  if key.lower().startswith('x-amz-'))):
            amz_headers[amz_header] = self.headers[amz_header]

        if 'x-amz-date' in amz_headers:
            buf += "\n"
        elif 'Date' in self.headers:
            buf += "%s\n" % self.headers['Date']

        for k in sorted(key.lower() for key in amz_headers):
            buf += "%s:%s\n" % (k, amz_headers[k])

        path = self._canonical_uri()
        if self.query_string:
            path += '?' + self.query_string
        if '?' in path:
            path, args = path.split('?', 1)
            params = []
            for key, value in sorted(self.params.items()):
                if key in ALLOWED_SUB_RESOURCES:
                    params.append('%s=%s' % (key, value) if value else key)
            if params:
                return '%s%s?%s' % (buf, path, '&'.join(params))

        return buf + path

    def _exists_put_used_sub_resources(self):
        """
        Check a request is included in PUT_USED_SUB_RESOURCES.
        """
        path = self._canonical_uri()
        if self.query_string:
            path += '?' + self.query_string
        if '?' in path:
            path, args = path.split('?', 1)
            for key, value in sorted(self.params.items()):
                if key in PUT_USED_SUB_RESOURCES:
                    return True
        return False

    def get_controller(self):
        subresource_controllers = {
            'acl': AclController,
            'delete': MultiObjectDeleteController,
            'lifecycle': LifecycleController,
            'location': LocationController,
            'logging': LoggingStatusController,
            'uploads': UploadsController,
            'partNumber': PartController,
            'versioning': VersioningController,
            'versions': BucketversionsController,
            'notification': UnsupportedController,
            'policy': UnsupportedController,
            'requestPayment': UnsupportedController,
            'torrent': UnsupportedController,
            'website': UnsupportedController,
            'cors': UnsupportedController,
            'tagging': UnsupportedController,
            'restore': UnsupportedController,
        }

        for r in subresource_controllers:
            if r in self.params:
                return subresource_controllers[r]

        # 'partNumber' has a higher priority than 'uploadId'
        if 'uploadId' in self.params:
            return UploadController

        if self.container_name and self.object_name:
            return ObjectController
        elif self.container_name:
            return BucketController

        return ServiceController

    def make_swift_req(self, method, path, query=None, body=None,
                       headers=None):
        env = self.environ.copy()

        if body is not None and 'HTTP_ETAG' in env:
            # Drop ETag header since the hash value was not based on the body
            del env['HTTP_ETAG']

        missing_meta = {}
        meta = [key for key in env.keys()
                if key.startswith('HTTP_X_AMZ_META_')]
        for key in meta:
            if utils.valid_header_name(key):
                env['HTTP_X_OBJECT_META_' + key[16:]] = env[key]
            else:
                missing_meta[key] = env[key]
            del env[key]
        if len(missing_meta.keys()) > 0:
            self.missing_meta = len(missing_meta.keys())

        if 'swift.proxy_access_log_made' in env:
            del(env['swift.proxy_access_log_made'])
        env['swift.source'] = 'S3'
        env['REQUEST_METHOD'] = method
        if self.keystone_token:
            # Need to skip S3 authorization since authtoken middleware
            # overwrites a tenant name in PATH_INFO
            env['HTTP_X_AUTH_TOKEN'] = self.keystone_token
            del env['HTTP_AUTHORIZATION']
        else:
            env['HTTP_X_AUTH_TOKEN'] = self.token
        env['PATH_INFO'] = path

        query_string = ''
        if query is not None:
            params = []
            for key, value in sorted(query.items()):
                if value is not None:
                    params.append('%s=%s' % (key, quote(str(value))))
                else:
                    params.append(key)
            query_string = '&'.join(params)
        env['QUERY_STRING'] = query_string

        # FIXME
        _, _, c, o = split_path(path, 0, 4, True)
        if c is not None and o is None and 'HTTP_RANGE' in env:
            del env['HTTP_RANGE']

        return Request.blank(quote(path), environ=env, body=body,
                             headers=headers)

    def get_response(self, app, method=None, path=None, headers=None,
                     body=None, query=None, success=[HTTP_OK], error={}):
        sw_req = self.make_swift_req(method=method, path=path, headers=headers,
                                     body=body, query=query)

        sw_req.environ['swift_owner'] = True  # needed to set ACL
        sw_req.environ['swift.authorize_override'] = True
        sw_req.environ['swift.authorize'] = lambda req: None

        sw_resp = sw_req.get_response(app)
        resp = S3Response(self, sw_req, sw_resp)
        status = resp.status_int

        if status in success:
            return resp

        if status in error.keys():
            err_resp = error[sw_resp.status_int]
            if isinstance(err_resp, tuple):
                raise err_resp[0](*err_resp[1:])
            else:
                raise err_resp()

        if status == HTTP_UNAUTHORIZED:
            raise SignatureDoesNotMatch()
        if status == HTTP_FORBIDDEN:
            raise AccessDenied()
        if status == HTTP_SERVICE_UNAVAILABLE:
            raise ServiceUnavailable()

        raise InternalError(s3_req=self.__dict__, sw_req=sw_req.__dict__,
                            sw_resp=sw_resp.__dict__)

    def get_expiration(self, app, account=None, container=None, obj=None,
                       headers=None):
        account = account or self.tenant_name
        container = container or self.container_name
        obj = obj or self.object_name

        path = '/v1/%s/%s/%s' % (account, container, obj)
        success = [HTTP_OK, HTTP_PARTIAL_CONTENT, HTTP_NOT_MODIFIED]
        error = {
            HTTP_NOT_FOUND: (NoSuchKey, obj),
            HTTP_PRECONDITION_FAILED: PreconditionFailed,
        }

        resp = self.get_response(app, 'HEAD', path, headers, '',
                                 success=success, error=error)

        creation_ts = resp.x_timestamp
        try:
            lifecycle = self.get_lifecycle_conf(app)
        except NoSuchLifecycleConfiguration:
            return None

        expiration = lifecycle[-1].to_header(obj, creation_ts)
        if expiration is not None:
            return expiration
        else:
            return None

    def check_expiration(self, app, obj, resp):
        creation_ts = resp.x_timestamp
        try:
            lifecycle = self.get_lifecycle_conf(app)
            if lifecycle.check_expiration(obj, creation_ts):
                # the object is expired
                raise NoSuchKey(obj)
        except NoSuchLifecycleConfiguration:
            return

        header = lifecycle[-1].to_header(obj, creation_ts)
        if header is not None:
            resp.headers['x-amz-expiration'] = header

    def get_swift_account(self, app, account=None, query=None, headers=None):
        account = account or self.tenant_name

        path = '/v1/%s' % (account)

        return self.get_response(app, 'GET', path, headers, '', query)

    def head_swift_container(self, app, account=None, container=None,
                             headers=None, access_check=False):
        account = account or self.tenant_name
        container = container or self.container_name

        path = '/v1/%s/%s' % (account, container)
        success = [HTTP_NO_CONTENT]
        error = {
            HTTP_NOT_FOUND: (NoSuchBucket, container),
        }

        resp = self.get_response(app, 'HEAD', path, headers, '',
                                 success=success, error=error)

        # to avoid infinite recurssion, the check must be after get_response()
        if access_check:
            if not self.has_permission(app, 'bucket', 'READ'):
                raise AccessDenied()

        return resp

    def get_swift_container(self, app, account=None, container=None,
                            query=None, headers=None, access_check=False):
        account = account or self.tenant_name
        container = container or self.container_name

        path = '/v1/%s/%s' % (account, container)
        success = [HTTP_OK, HTTP_NO_CONTENT]
        error = {
            HTTP_NOT_FOUND: (NoSuchBucket, container),
        }

        if access_check:
            if not self.has_permission(app, 'bucket', 'READ'):
                raise AccessDenied()

        return self.get_response(app, 'GET', path, headers, '', query,
                                 success=success, error=error)

    def put_swift_container(self, app, account=None, container=None,
                            headers=None):
        account = account or self.tenant_name
        container = container or self.container_name

        path = '/v1/%s/%s' % (account, container)
        success = [HTTP_CREATED, HTTP_NO_CONTENT]
        error = {
            HTTP_ACCEPTED: (BucketAlreadyExists, container),
        }

        return self.get_response(app, 'PUT', path, headers, '',
                                 success=success, error=error)

    def post_swift_container(self, app, account=None, container=None,
                             headers=None):
        account = account or self.tenant_name
        container = container or self.container_name

        path = '/v1/%s/%s' % (account, container)
        success = [HTTP_NO_CONTENT]
        error = {
            HTTP_NOT_FOUND: (NoSuchBucket, container),
        }

        return self.get_response(app, 'POST', path, headers, '',
                                 success=success, error=error)

    def delete_swift_container(self, app, account=None, container=None,
                               headers=None, access_check=False):
        account = account or self.tenant_name
        container = container or self.container_name

        path = '/v1/%s/%s' % (account, container)
        success = [HTTP_NO_CONTENT]
        error = {
            HTTP_NOT_FOUND: (NoSuchBucket, container),
            HTTP_CONFLICT: BucketNotEmpty,
        }

        return self.get_response(app, 'DELETE', path, headers, '',
                                 success=success, error=error)

    def head_swift_object(self, app, account=None, container=None, obj=None,
                          headers=None, access_check=False):
        account = account or self.tenant_name
        container = container or self.container_name
        obj = obj or self.object_name

        path = '/v1/%s/%s/%s' % (account, container, obj)
        success = [HTTP_OK, HTTP_PARTIAL_CONTENT, HTTP_NOT_MODIFIED]
        error = {
            HTTP_NOT_FOUND: (NoSuchKey, obj),
            HTTP_PRECONDITION_FAILED: PreconditionFailed,
        }

        resp = self.get_response(app, 'HEAD', path, headers, '',
                                 success=success, error=error)

        if access_check:
            if resp.delete_marker:
                    # TODO: set proper headers
                    headers = HeaderKeyDict(resp.headers)
                    if 'versionId' in self.params:
                        if headers.get('Content-Length'):
                            del(headers['Content-Length'])
                            raise MethodNotAllowed(headers=headers,
                                                   method='HEAD')
                    else:
                        resp.headers['x-amz-version-id'] = 'null'
                        resp.headers['x-amz-delete-marker'] = True
                        raise NoSuchKey(key=obj, headers=resp.headers)

            if not self.has_permission(app, 'object', 'READ'):
                raise AccessDenied()

            self.check_expiration(app, obj, resp)

        return resp

    def get_swift_object(self, app, account=None, container=None, obj=None,
                         headers=None, access_check=False):
        account = account or self.tenant_name
        container = container or self.container_name
        obj = obj or self.object_name

        path = '/v1/%s/%s/%s' % (account, container, obj)
        success = [HTTP_OK, HTTP_PARTIAL_CONTENT, HTTP_NOT_MODIFIED]
        error = {
            HTTP_NOT_FOUND: (NoSuchKey, obj),
            HTTP_PRECONDITION_FAILED: PreconditionFailed,
            HTTP_REQUESTED_RANGE_NOT_SATISFIABLE: InvalidRange,
        }

        resp = self.get_response(app, 'GET', path, headers, '',
                                 success=success, error=error)
        if account != '.swift3':
            self.object_size = resp.content_length

        if access_check:
            if resp.delete_marker:
                # TODO: set proper headers
                headers = HeaderKeyDict(resp.headers)
                if 'versionId' in self.params:
                    if headers.get('Content-Length'):
                        del(headers['Content-Length'])
                        self.object_size = 0
                        raise MethodNotAllowed(headers=headers, method='GET')
                else:
                    if headers.get('Content-Length'):
                        del(headers['Content-Length'])
                        self.object_size = 0
                    headers['x-amz-version-id'] = 'null'
                    headers['x-amz-delete-marker'] = True
                    raise NoSuchKey(key=obj, headers=headers)

            if not self.has_permission(app, 'object', 'READ'):
                raise AccessDenied()

            self.check_expiration(app, obj, resp)

        return resp

    def _get_copy_source(self, app):
        if self.content_length > 0:
            err_msg = 'The request included a body. Requests of this' \
                ' type must not include a non-empty body.'
            raise InvalidRequest(err_msg)

        if self.copy_source[0] != '/':
            copy_source = '/' + self.copy_source
        else:
            copy_source = self.copy_source
        bucket, obj = split_path(copy_source, 0, 2, True)

        version_id = None
        if '?versionId=' in obj:
            obj, version_id = obj.split('?versionId=')

        if not utils.valid_container_name(bucket):
            raise NoSuchBucket(bucket)

        if self.metadata_directive != 'REPLACE' and \
                bucket == self.container_name and obj == self.object_name:
            err_msg = "This copy request is illegal because it is trying" \
                " to copy an object to itself without changing the" \
                " object's metadata."
            raise InvalidRequest(err_msg)

        # TODO: create another S3Request to simplify code
        orig_bucket = self.container_name
        orig_obj = self.object_name
        orig_env = self.environ.copy()
        self.container_name = bucket
        self.object_name = obj
        self.environ.update(self.copy_source_environ)

        if version_id is not None:
            c, o = self.find_version_object(app, self.object_name, version_id)
            self.container_name = c
            self.object_name = o

        resp = self.head_swift_object(app)
        if resp.delete_marker:
            headers = HeaderKeyDict(resp.headers)
            if headers.get('Content-Length'):
                del(headers['Content-Length'])
                self.object_size = 0
                raise NoSuchKey(orig_obj)

        src_resp = self.get_swift_object(app)

        if src_resp.status_int in {HTTP_NOT_MODIFIED,
                                   HTTP_PRECONDITION_FAILED}:
            raise PreconditionFailed()

        self.container_name = orig_bucket
        self.object_name = orig_obj
        self.environ = orig_env
        self.headers = HeaderEnvironProxy(self.environ)

        return src_resp

    def put_swift_object(self, app, account=None, container=None, obj=None,
                         query=None, body=None, headers=None,
                         access_check=False):
        account = account or self.tenant_name
        container = container or self.container_name
        obj = obj or self.object_name

        if self.copy_source is not None:
            src_resp = self._get_copy_source(app)
            body = src_resp.body  # FIXME: use app_iter

            if self.metadata_directive == 'COPY':
                headers = headers or {}
                # remove user's metadata
                for h in headers:
                    if h.lower().startswith('x-amz-meta-'):
                        del headers[h]

                for h in src_resp.headers:
                    if h.lower().startswith('x-amz-meta-'):
                        self.headers[h] = src_resp.headers[h]
                self.missing_meta = src_resp.headers.get('x-amz-missing-meta')

        # set object size
        if account != '.swift3':
            if self.copy_source is not None:
                self.object_size = len(body)
            else:
                self.object_size = self.content_length

        # set version id if necessary
        if account != '.swift3' and container == self.container_name:
            headers = headers or {}
            p_resp = self.head_swift_container(app)
            if p_resp.versioning_status == 'Enabled':
                self.versioned = 'true'

        path = '/v1/%s/%s/%s' % (account, container, obj)
        success = [HTTP_CREATED]
        error = {
            HTTP_NOT_FOUND: (NoSuchBucket, container),
            HTTP_UNPROCESSABLE_ENTITY: InvalidDigest,
            HTTP_REQUEST_ENTITY_TOO_LARGE: EntityTooLarge,
            HTTP_LENGTH_REQUIRED: MissingContentLength,
        }

        if access_check:
            if not self.has_permission(app, 'bucket', 'WRITE'):
                raise AccessDenied()

        resp = self.get_response(app, 'PUT', path, headers, body, query,
                                 success=success, error=error)

        if self.versioned:
            version_id = str(VersionId(self.get_object_ts(app)))
            resp.headers['x-amz-version-id'] = version_id

        if self.copy_source is not None:
            if 'x-amz-version-id' in src_resp.headers:
                resp.headers['x-amz-copy-source-version-id'] = \
                    src_resp.headers['x-amz-version-id']

        return resp

    # If versioning_check is True, swift3 will create a delete marker for a
    # versioned object.
    def delete_swift_object(self, app, account=None, container=None, obj=None,
                            headers=None, access_check=False,
                            versioning_check=False):
        account = account or self.tenant_name
        container = container or self.container_name
        obj = obj or self.object_name

        # do HEAD first to check expiration
        resp = self.head_swift_object(app, account, container, obj, headers)

        if access_check:
            if not self.has_permission(app, 'bucket', 'WRITE'):
                raise AccessDenied()

            self.check_expiration(app, obj, resp)

        resp_c = self.head_swift_container(app)
        if versioning_check and \
                resp_c.versioning_status in ('Enabled', 'Suspended'):
            self.delete_marker = 'true'
            self.object_owner = self.user_id
            self.object_timestamp = utils.normalized_currrent_timestamp()
            resp = self.put_swift_object(app, account, container, obj,
                                         None, '', headers)
            if not resp.headers['x-amz-version-id']:
                if resp_c.versioning_status == 'Enabled':
                    version_id = str(VersionId(self.get_object_ts(app)))
                else:
                    version_id = 'null'
                resp.headers['x-amz-version-id'] = version_id
            resp.headers['x-amz-delete-marker'] = self.delete_marker
            return resp

        path = '/v1/%s/%s/%s' % (account, container, obj)

        success = [HTTP_NO_CONTENT]
        error = {
            HTTP_NOT_FOUND: (NoSuchKey, obj),
        }

        return self.get_response(app, 'DELETE', path, headers, '',
                                 success=success, error=error)

    def get_swift3_config(self, app, container=None, obj=None, query=None,
                          headers=None):
        if obj:
            return self.get_swift_object(app, account='.swift3',
                                         container=container, obj=obj,
                                         headers=headers)
        else:
            return self.get_swift_container(app, account='.swift3',
                                            container=container,
                                            query=query, headers=headers)

    def head_swift3_config(self, app, container=None, obj=None, query=None,
                           headers=None):
        if obj:
            return self.head_swift_object(app, account='.swift3',
                                          container=container, obj=obj,
                                          headers=headers)
        else:
            return self.head_swift_container(app, account='.swift3',
                                             container=container,
                                             query=query, headers=headers)

    def put_swift3_config(self, app, container=None, obj=None,
                          body=None, headers=None):
        if obj:
            return self.put_swift_object(app, account='.swift3',
                                         container=container, obj=obj,
                                         body=body,
                                         headers=headers)
        else:
            return self.put_swift_container(app, account='.swift3',
                                            container=container,
                                            headers=headers)

    def delete_swift3_config(self, app, container=None, obj=None,
                             headers=None):
        if obj:
            return self.delete_swift_object(app, account='.swift3',
                                            container=container, obj=obj,
                                            headers=headers)
        else:
            return self.delete_swift_container(app, account='.swift3',
                                               container=container,
                                               headers=headers)

    def get_s3_acl(self, app, version_id=None, access_check=False):
        if self.object_name:
            if access_check:
                account = self.tenant_name
                container = self.container_name
                obj = self.object_name

                if version_id:
                    container, obj = \
                        self.find_version_object(app,
                                                 self.object_name,
                                                 version_id)

                path = '/v1/%s/%s/%s' % (account, container, obj)
                success = [HTTP_OK, HTTP_PARTIAL_CONTENT, HTTP_NOT_MODIFIED]
                error = {
                    HTTP_NOT_FOUND: (NoSuchKey, obj),
                }
                resp = self.get_response(app, 'HEAD', path, None, '',
                                         success=success, error=error)
                if resp.delete_marker:
                    # TODO: set proper headers
                    headers = HeaderKeyDict(resp.headers)
                    if headers.get('Content-Length'):
                        del(headers['Content-Length'])
                        raise MethodNotAllowed(headers=headers, method='GET')

                self.check_expiration(app, obj, resp)

                if not self.has_permission(app, 'object', 'READ_ACP'):
                    raise AccessDenied()

            if version_id:
                container, obj = self.find_version_object(app,
                                                          self.object_name,
                                                          version_id)
                resp = self.head_swift_object(app,
                                              container=container,
                                              obj=obj)
                object_timestamp = resp.object_timestamp
            else:
                object_timestamp = self.get_object_ts(app)

            container = self.container_name
            object_name = self.object_name
            obj = '%s/%s/%s/%s/%s' % (self.tenant_name, container,
                                      self.get_container_ts(app),
                                      object_name,
                                      object_timestamp)
        else:
            if access_check:
                if not self.has_permission(app, 'bucket', 'READ_ACP'):
                    raise AccessDenied()

            resp = self.head_swift_container(app)
            obj = '%s/%s/%s' % (self.tenant_name, self.container_name,
                                self.get_container_ts(app))
        try:
            resp = self.get_swift3_config(app, 'acl', obj, '')
            return ACL(xml=resp.body)
        except NoSuchKey:
            # don't return ACLPrivate directly to resolve owner id
            return ACL(xml=ACLPrivate().to_xml(self.get_bucket_owner(app),
                                               self.get_object_owner(app)))

    def get_parent_s3_acl(self, app):
        resp = self.head_swift_container(app)

        container = self.container_name
        if '+' in container:
            container = container.split('+')[0]
        obj = '%s/%s/%s' % (self.tenant_name, container,
                            self.get_container_ts(app))

        try:
            resp = self.get_swift3_config(app, 'acl', obj, '')
            return ACL(xml=resp.body)
        except NoSuchKey:
            # don't return ACLPrivate directly to resolve owner id
            return ACL(xml=ACLPrivate().to_xml(self.get_bucket_owner(app)))

    def get_s3_acl_xml(self, app, version_id, access_check=False):
        acl = self.get_s3_acl(app, version_id, access_check)
        return acl.to_xml(self.get_bucket_owner(app),
                          self.get_object_owner(app))

    def put_s3_acl(self, app, logger, headers={}, xml=None,
                   version_id=None, access_check=False):
        if self.object_name:
            if access_check:
                account = self.tenant_name
                container = self.container_name
                obj = self.object_name

                if version_id:
                    container, obj = self.find_version_object(app,
                                                              self.object_name,
                                                              version_id)
                path = '/v1/%s/%s/%s' % (account, container, obj)
                success = [HTTP_OK, HTTP_PARTIAL_CONTENT, HTTP_NOT_MODIFIED]
                error = {
                    HTTP_NOT_FOUND: (NoSuchKey, obj),
                }
                resp_o = self.get_response(app, 'HEAD', path, None, '',
                                           success=success, error=error)
                if resp_o.delete_marker:
                    # TODO: set proper headers
                    headers = HeaderKeyDict(resp_o.headers)
                    if headers.get('Content-Length'):
                        del(headers['Content-Length'])
                        raise MethodNotAllowed(headers=headers, method='PUT')

                self.check_expiration(app, obj, resp_o)

                if not self.has_permission(app, 'object', 'WRITE_ACP'):
                    raise AccessDenied()

            resp_c = self.head_swift_container(app)
            if resp_c.versioning_status == 'Enabled':
                self.versioned = 'true'

            if version_id:
                container, obj = self.find_version_object(app,
                                                          self.object_name,
                                                          version_id)
                resp = self.head_swift_object(app,
                                              container=container,
                                              obj=obj)
                object_timestamp = resp.object_timestamp
            else:
                object_timestamp = self.get_object_ts(app)
                version_id = str(VersionId(self.get_object_ts(app)))

            obj = '%s/%s/%s/%s/%s' % (self.tenant_name,
                                      self.container_name,
                                      self.get_container_ts(app),
                                      self.object_name,
                                      object_timestamp)
        else:
            if access_check:
                if not self.has_permission(app, 'bucket', 'WRITE_ACP'):
                    raise AccessDenied()

            obj = '%s/%s/%s' % (self.tenant_name, self.container_name,
                                self.get_container_ts(app))

        acl = ACL(headers=headers, xml=xml)

        if not utils.ALLOW_CONTAINER_PUBLIC_WRITE:
            for p, g in acl:
                if p in ['WRITE', 'FULL_CONTROL'] \
                   and isinstance(g, AllUsers):
                    raise InvalidArgument('ACL', p,
                                          'Unsupported ACL for AllUsers')

        if acl.owner and acl.owner != self.user_id:
            raise AccessDenied()

        try:
            self.put_swift3_config(app, 'acl', '')
        except BucketAlreadyExists:
            pass

        bucket_owner = self.get_bucket_owner(app)
        object_owner = self.get_object_owner(app)

        for permission, grantee in acl:
            if isinstance(grantee, Owner):
                grantee = grantee.to_user(bucket_owner, object_owner)

            if self.object_name:
                resource = 'object /%s/%s' % (self.container_name,
                                              self.object_name)
            else:
                resource = 'bucket /%s' % self.container_name

            logger.info('Grant %s %s permission on the %s' %
                        (grantee, permission, resource))

        resp = self.put_swift3_config(app, 'acl', obj,
                                      acl.to_xml(bucket_owner, object_owner))

        return resp

    def has_permission(self, app, resource, permission):
        if resource == 'object':
            owner = self.get_object_owner(app)
        elif resource == 'bucket':
            owner = self.get_bucket_owner(app)
        else:
            raise InternalError()

        # owners have full control permission
        if self.user_id == owner:
            return True

        if resource == 'object':
            acl = self.get_s3_acl(app)
        else:
            acl = self.get_parent_s3_acl(app)

        if self.user_id in acl['FULL_CONTROL']:
            return True

        return self.user_id in acl[permission]

    def get_swift3_meta_data(self, app, resource, name, container=None):
        container = container or self.container_name

        key = 'x-%s-meta-[swift3]-%s' % (resource, name)
        if resource == 'container':
            resp = self.head_swift_container(app, container=container)
        else:
            resp = self.head_swift_object(app)
        return resp.swift3_headers.get(key, 'undefined')

    def get_bucket_owner(self, app, container=None):
        container = container or self.container_name
        if '+' in container:
            container = container.split('+')[0]

        bucket_owner = self.get_swift3_meta_data(app, 'container', 'owner',
                                                 container=container)

        if bucket_owner == 'undefined':
            # get owner based on ACL
            resp = self.head_swift_container(app, container=container)
            bucket_owner = utils.get_owner_from_acl(resp.sw_headers)

        return bucket_owner

    def get_object_owner(self, app):
        object_owner = None
        if self.object_name:
            object_owner = self.get_swift3_meta_data(app, 'object', 'owner')
        return object_owner

    def get_versioning(self, app):
        resp = self.head_swift_container(app)

        conf_elem = Element('VersioningConfiguration')
        if resp.versioning_status in ('Enabled', 'Suspended'):
            SubElement(conf_elem, 'Status').text = resp.versioning_status
        elif resp.versioning_status:
            raise InternalError()

        return tostring(conf_elem)

    def put_versioning(self, app):
        try:
            self.get_latest_lifecycle_conf_xml(app)

            err_msg = 'Versioning is currently not supported on a bucket ' \
                'with lifecycle configuration. Delete lifecycle ' \
                'configuration before setting versioning for a bucket.'
            raise InvalidBucketState(err_msg)
        except NoSuchLifecycleConfiguration:
            pass

        try:
            conf_elem = fromstring(self.body, 'VersioningConfiguration')
        except Exception:
            raise MalformedXML()
        status_elem = conf_elem.find('./{*}Status')
        if status_elem is None:
            msg = 'The Versioning element must be specified'
            raise IllegalVersioningConfigurationException(msg)
        status = status_elem.text

        # create a container for version objects
        version_container = self.container_name + '+versions'
        try:
            self.put_swift_container(app, container=version_container)
        except BucketAlreadyExists:
            pass

        self.versioning_status = status

        headers = {'X-Versions-Location': version_container}
        return self.post_swift_container(app, headers=headers)

    def collect_versions(self, app):
        # returns [(key, v_id, delete_marker, is_latest, last_modified, etag,
        # size, owner)]
        versions = []

        # search version container
        version_container = self.container_name + '+versions'
        try:
            resp = self.get_swift_container(app, container=version_container,
                                            query={'format': 'json'})
            for v in utils.json_to_objects(resp.body):
                key, _ = v['name'][3:].rsplit('/', 1)
                resp = self.head_swift_object(app, container=version_container,
                                              obj=v['name'])
                version_id = VersionId(resp.object_timestamp, resp.versioned)
                if not resp.versioned:
                    # remove older null versioned objects
                    versions = [_v for _v in versions
                                if _v[0] != key or str(_v[1]) != 'null']

                versions.append((key, version_id, resp.delete_marker, 'false',
                                 v['last_modified'], v['hash'], v['bytes'],
                                 resp.object_owner))
        except NoSuchBucket:
            # probably, versioning is not enabled on this bucket
            pass

        # search current container
        resp = self.get_swift_container(app, query={'format': 'json'})
        objects = utils.json_to_objects(resp.body)
        for o in objects:
            resp = self.head_swift_object(app, obj=o['name'])
            version_id = VersionId(resp.object_timestamp, resp.versioned)
            if not resp.versioned:
                # remove older null versioned objects
                versions = [v for v in versions
                            if v[0] != o['name'] or str(v[1]) != 'null']
            versions.append((o['name'], version_id, resp.delete_marker, 'true',
                             o['last_modified'], o['hash'], o['bytes'],
                             resp.object_owner))

        versions.sort()
        return versions

    def find_version_object(self, app, obj, version_id):
        # This method removes older null versioned objects except the latest
        # one.
        latest_null_version_obj = None
        if version_id == 'null':
            target_ts = 'undefined'
        else:
            target_ts = VersionId.parse(version_id).ts

        # search version container
        version_container = self.container_name + '+versions'
        try:
            resp = self.get_swift_container(app, container=version_container,
                                            query={'format': 'json'})
            for v in utils.json_to_objects(resp.body):
                key, _ = v['name'][3:].rsplit('/', 1)
                if key != obj:
                    continue

                resp = self.head_swift_object(app, container=version_container,
                                              obj=v['name'])

                if resp.versioned:
                    if resp.object_timestamp == target_ts:
                        return version_container, v['name']
                else:
                    if latest_null_version_obj:
                        # remove the older one
                        self.delete_swift_object(app,
                                                 container=version_container,
                                                 obj=latest_null_version_obj)
                    latest_null_version_obj = v['name']
        except NoSuchBucket:
            # probably, versioning is not enabled on this bucket
            raise NoSuchVersion(obj, version_id)

        # check current container
        try:
            resp = self.head_swift_object(app, obj=obj)
            if not resp.versioned:
                if latest_null_version_obj:
                    # remove the older one
                    self.delete_swift_object(app, container=version_container,
                                             obj=latest_null_version_obj)
                return self.container_name, obj
            else:
                if resp.object_timestamp == target_ts:
                    return self.container_name, obj

            if version_id == 'null' and latest_null_version_obj:
                return version_container, latest_null_version_obj
        except NoSuchKey:
            raise NoSuchVersion(obj, version_id)

        raise NoSuchVersion(obj, version_id)

    def get_logging_conf(self, app):
        resp = self.head_swift_container(app)
        obj = '%s/%s/%s' % (self.tenant_name, self.container_name,
                            self.get_container_ts(app))
        try:
            resp = self.get_swift3_config(app, 'logging_conf', obj, '')
            return LoggingStatus(resp.body)
        except NoSuchKey:
            # logging is disabled
            return LoggingStatus()

    def get_logging_conf_xml(self, app):
        conf = self.get_logging_conf(app)
        return conf.to_xml()

    def check_logging_permission(self, app, target_bucket):
        orig_bucket = self.container_name  # TODO: use 'with'
        orig_object = self.object_name

        self.container_name = target_bucket
        self.object_name = None

        acl = self.get_s3_acl(app, access_check=True)
        if utils.LOG_DELIVERY_USER in acl['FULL_CONTROL']:
            pass
        elif utils.LOG_DELIVERY_USER in acl['READ_ACP'] and \
                utils.LOG_DELIVERY_USER in acl['WRITE']:
            pass
        else:
            msg = 'You must give the log-delivery group WRITE and READ_ACP ' \
                'permissions to the target bucke'
            raise InvalidTargetBucketForLogging(target_bucket, msg)

        self.object_name = orig_object
        self.container_name = orig_bucket

    def put_logging_conf(self, app):
        conf = LoggingStatus(xml=self.body)

        obj = '%s/%s/%s' % (self.tenant_name, self.container_name,
                            self.get_container_ts(app))
        try:
            self.put_swift3_config(app, 'logging_conf', '')
        except BucketAlreadyExists:
            pass

        if conf.target_bucket:
            try:
                resp = self.head_swift_container(app,
                                                 container=conf.target_bucket)
            except NoSuchBucket:
                msg = 'The target bucket for logging does not exist'
                raise InvalidTargetBucketForLogging(conf.target_bucket,
                                                    msg)
            if resp.bucket_owner != self.user_id:
                msg = 'The owner for the bucket to be logged and the target ' \
                    'bucket must be the same.'
                raise InvalidTargetBucketForLogging(conf.target_bucket, msg)

            self.check_logging_permission(app, conf.target_bucket)

        return self.put_swift3_config(app, 'logging_conf', obj,
                                      conf.to_xml())

    def get_lifecycle_conf(self, app):
        if self.container_name.endswith('+versions'):
            # We cannot set versioning and lifecycle at the same time
            raise NoSuchLifecycleConfiguration()

        resp = self.head_swift_container(app)

        query = {
            'format': 'json',
            'prefix': '%s/%s/%s' % (self.tenant_name, self.container_name,
                                    self.get_container_ts(app))
        }
        try:
            resp = self.get_swift3_config(app, 'lifecycle_rules', query=query)
            objects = utils.json_to_objects(resp.body)
            confs = []
            for o in objects:
                resp = self.get_swift3_config(app, 'lifecycle_rules',
                                              o['name'], '')

                _, _, _, rule_ts = split_path('/' + o['name'], 4, 4)
                confs.append(LifecycleConf(resp.body, rule_ts))

            if len(confs) == 0:
                raise NoSuchLifecycleConfiguration()

            return LifecycleConfHistory(confs)
        except (NoSuchKey, NoSuchBucket):
            # lifecycle is not enabled
            raise NoSuchLifecycleConfiguration()

    def get_latest_lifecycle_conf_xml(self, app):
        confs = self.get_lifecycle_conf(app)
        if len(confs) == 0:
            raise NoSuchLifecycleConfiguration()

        conf = confs[-1]
        if len(conf.rules) == 0:
            # the lifecycle conf was deleted
            raise NoSuchLifecycleConfiguration()

        return conf.to_xml()

    def put_lifecycle_conf(self, app):
        conf = LifecycleConf(xml=self.body)
        if len(conf.rules) == 0:
            # We cannot do this check with XML Schema since we use zero rule
            # lifecycle conf to mark the configuration is deleted.
            raise MalformedXML()

        resp = self.head_swift_container(app)
        if resp.versioning_status in ('Enabled', 'Suspended'):
            err_msg = 'Lifecycle configuration is currently not supported ' \
                'on a versioned bucket.'
            raise InvalidBucketState(err_msg)

        obj = '%s/%s/%s/%s' % (self.tenant_name, self.container_name,
                               self.get_container_ts(app), conf.timestamp)

        try:
            self.put_swift3_config(app, 'lifecycle_rules', '')
        except BucketAlreadyExists:
            pass

        return self.put_swift3_config(app, 'lifecycle_rules', obj,
                                      conf.to_xml())

    def delete_lifecycle_conf(self, app):
        conf = LifecycleConf(xml=self.body)

        obj = '%s/%s/%s/%s' % (self.tenant_name, self.container_name,
                               self.get_container_ts(app), conf.timestamp)

        try:
            self.put_swift3_config(app, 'lifecycle_rules', '')
        except BucketAlreadyExists:
            pass

        return self.put_swift3_config(app, 'lifecycle_rules', obj,
                                      conf.to_xml())

    def get_upload_status(self, app, upload_id):
        try:
            obj = '%s/%s/%s/%s/%s' % (self.tenant_name,
                                      self.container_name,
                                      self.get_container_ts(app),
                                      self.object_name, upload_id)

            resp = self.get_swift3_config(app, 'upload_in_progress', obj)
            xml = resp.body
            return xml
        except NoSuchKey:
            raise NoSuchUpload(upload_id=upload_id)

    def head_upload_status(self, app, upload_id):
        try:
            obj = '%s/%s/%s/%s/%s' % (self.tenant_name,
                                      self.container_name,
                                      self.get_container_ts(app),
                                      self.object_name, upload_id)

            resp = self.head_swift3_config(app, 'upload_in_progress', obj)
            return resp.headers
        except NoSuchKey:
            raise NoSuchUpload(upload_id=upload_id)

    def put_upload_status(self, app, upload_id):
        xml = self.body if self.body else None
        acl = ACL(headers=self.headers, xml=xml)
        if acl.owner and acl.owner != self.user_id:
            raise AccessDenied()

        if not self.has_permission(app, 'bucket', 'WRITE'):
            raise AccessDenied()

        obj = '%s/%s/%s/%s/%s' % (self.tenant_name,
                                  self.container_name,
                                  self.get_container_ts(app),
                                  self.object_name, upload_id)
        try:
            self.put_swift3_config(app, 'upload_in_progress')
        except BucketAlreadyExists:
            pass

        return self.put_swift3_config(app, 'upload_in_progress', obj,
                                      acl.to_xml(self.get_bucket_owner(app),
                                                 self.user_id))

    def delete_upload_status(self, app, upload_id):
        try:
            obj = '%s/%s/%s/%s/%s' % (self.tenant_name,
                                      self.container_name,
                                      self.get_container_ts(app),
                                      self.object_name, upload_id)

            return self.delete_swift3_config(app, 'upload_in_progress', obj)
        except NoSuchKey:
            raise NoSuchUpload(upload_id=upload_id)
