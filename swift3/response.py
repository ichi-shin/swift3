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
from UserDict import DictMixin
from functools import partial

from swift.common import swob

from swift3.utils import snake_to_camel, sysmeta_prefix
from swift3.etree import Element, SubElement, tostring


class HeaderKey(str):
    """
    A string object that normalizes string as S3 clients expect with title().
    """
    def title(self):
        if self.lower() == 'etag':
            # AWS Java SDK expects only 'ETag'.
            return 'ETag'
        if self.lower().startswith('x-amz-'):
            # AWS headers returned by S3 are lowercase.
            return self.lower()
        if self.lower().startswith('x-rgw-'):
            # ceph/s3tests expects the header is lowercase.
            return self.lower()
        return str.title(self)


class HeaderKeyDict(swob.HeaderKeyDict):
    """
    Similar to the HeaderKeyDict class in Swift, but its key name is normalized
    as S3 clients expect.
    """
    def __getitem__(self, key):
        return swob.HeaderKeyDict.__getitem__(self, HeaderKey(key))

    def __setitem__(self, key, value):
        return swob.HeaderKeyDict.__setitem__(self, HeaderKey(key), value)

    def __contains__(self, key):
        return swob.HeaderKeyDict.__contains__(self, HeaderKey(key))

    def __delitem__(self, key):
        return swob.HeaderKeyDict.__delitem__(self, HeaderKey(key))

    def get(self, key, default=None):
        return swob.HeaderKeyDict.get(self, HeaderKey(key), default)

    def pop(self, key, default=None):
        return swob.HeaderKeyDict.pop(self, HeaderKey(key), default)


class ResponseBase(object):
    """
    Base class for swift3 responses.
    """
    pass


class Response(ResponseBase, swob.Response):
    """
    Similar to the Response class in Swift, but uses our HeaderKeyDict for
    headers instead of Swift's HeaderKeyDict.  This also translates Swift
    specific headers to S3 headers.
    """
    def __init__(self, *args, **kwargs):
        swob.Response.__init__(self, *args, **kwargs)

        if self.etag:
            # add double quotes to the etag header
            self.etag = self.etag

        swift3_headers = HeaderKeyDict()
        sw_headers = HeaderKeyDict()
        headers = HeaderKeyDict()
        meta = {}

        for key, val in self.headers.iteritems():
            _key = key.lower()
            if _key.startswith(sysmeta_prefix('object')) or \
                    _key.startswith(sysmeta_prefix('container')):
                swift3_headers[key] = val
            else:
                sw_headers[key] = val

        # Handle swift3 internal headers
        for key, val in swift3_headers.iteritems():
            _key = key.lower()
            if _key == 'x-object-meta-[swift3]-version-id' and val != 'null':
                headers['x-amz-version-id'] = val
            if _key == 'x-object-meta-[swift3]-delete-marker':
                headers['x-amz-delete-marker'] = val
            if _key == 'x-object-meta-[swift3]-missing-meta':
                headers['x-amz-missing-meta'] = val

        # Handle swift headers
        for key, val in sw_headers.iteritems():
            _key = key.lower()

            if _key.startswith('x-object-meta-'):
                meta[_key[14:]] = val
                headers['x-amz-meta-' + _key[14:]] = val
            elif _key in ('content-length', 'content-type',
                          'content-range', 'content-encoding',
                          'etag', 'last-modified'):
                headers[key] = val
            elif _key.startswith('x-rgw-'):
                headers[key] = val
            elif _key == 'x-container-object-count':
                # for ceph/s3tests
                headers['x-rgw-object-count'] = val
            elif _key == 'x-container-bytes-used':
                # for ceph/s3tests
                headers['x-rgw-bytes-used'] = val

        self.headers = headers

        from swift3.subresource import decode_subresource
        self.bucket_info = {
            'ts': sw_headers['x-timestamp'],
            'versioning': decode_subresource('container', 'versioning',
                                             swift3_headers),
            'lifecycle': decode_subresource('container', 'lifecycle',
                                            swift3_headers),
            'logging': decode_subresource('container', 'logging',
                                          swift3_headers),
            'acl': decode_subresource('container', 'acl', swift3_headers),
        }
        self.object_info = {
            'ts': sw_headers['x-timestamp'],
            'version_id': swift3_headers['x-object-meta-[swift3]-version-id'],
            'delete_marker': swift3_headers[
                'x-object-meta-[swift3]-delete-marker'],
            'acl': decode_subresource('object', 'acl', swift3_headers),
            'etag': self.etag,
            'bytes': self.content_length,
            'last_modified': str(self.last_modified),
            'meta': meta,
        }

    @classmethod
    def from_swift_resp(cls, sw_resp):
        """
        Create a new S3 response object based on the given Swift response.
        """
        if sw_resp.app_iter:
            body = None
            app_iter = sw_resp.app_iter
        else:
            body = sw_resp.body
            app_iter = None

        resp = Response(status=sw_resp.status, headers=sw_resp.headers,
                        request=sw_resp.request, body=body, app_iter=app_iter,
                        conditional_response=sw_resp.conditional_response)
        resp.environ.update(sw_resp.environ)
        resp.sw_resp = sw_resp  # for debug information

        return resp


HTTPOk = partial(Response, status=200)
HTTPCreated = partial(Response, status=201)
HTTPAccepted = partial(Response, status=202)
HTTPNoContent = partial(Response, status=204)


class ErrorResponse(ResponseBase, swob.HTTPException):
    """
    S3 error object.

    Reference information about S3 errors is available at:
    http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
    """
    _status = ''
    _msg = ''
    _code = ''

    def __init__(self, msg=None, *args, **kwargs):
        if msg:
            self._msg = msg
        if not self._code:
            self._code = self.__class__.__name__

        self.info = kwargs.copy()
        for reserved_key in ('headers', 'body'):
            if self.info.get(reserved_key):
                del(self.info[reserved_key])

        swob.HTTPException.__init__(self, status=self._status,
                                    app_iter=self._body_iter(),
                                    content_type='text/xml', *args, **kwargs)
        self.headers = HeaderKeyDict(self.headers)

    def _body_iter(self):
        error_elem = Element('Error')
        SubElement(error_elem, 'Code').text = self._code
        SubElement(error_elem, 'Message').text = self._msg
        if 'swift.trans_id' in self.environ:
            request_id = self.environ['swift.trans_id']
            SubElement(error_elem, 'RequestId').text = request_id

        self._dict_to_etree(error_elem, self.info)

        yield tostring(error_elem, use_s3ns=False)

    def _dict_to_etree(self, parent, d):
        for key, value in d.items():
            tag = re.sub('\W', '', snake_to_camel(key))
            elem = SubElement(parent, tag)

            if isinstance(value, (dict, DictMixin)):
                self._dict_to_etree(elem, value)
            else:
                try:
                    elem.text = str(value)
                except ValueError:
                    # We set an invalid string for XML.
                    elem.text = '(invalid string)'


class AccessDenied(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Access Denied.'


class AccountProblem(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'There is a problem with your AWS account that prevents the ' \
           'operation from completing successfully.'


class AmbiguousGrantByEmailAddress(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The e-mail address you provided is associated with more than ' \
           'one account.'


class BadDigest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The Content-MD5 you specified did not match what we received.'


class BucketAlreadyExists(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The requested bucket name is not available. The bucket ' \
           'namespace is shared by all users of the system. Please select a ' \
           'different name and try again.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class BucketAlreadyOwnedByYou(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'Your previous request to create the named bucket succeeded and ' \
           'you already own it.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class BucketNotEmpty(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The bucket you tried to delete is not empty.'


class CredentialsNotSupported(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'This request does not support credentials.'


class CrossLocationLoggingProhibited(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Cross location logging not allowed. Buckets in one geographic ' \
           'location cannot log information to a bucket in another location.'


class EntityTooSmall(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your proposed upload is smaller than the minimum allowed object ' \
           'size.'


class EntityTooLarge(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your proposed upload exceeds the maximum allowed object size.'


class ExpiredToken(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token has expired.'


class IllegalVersioningConfigurationException(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The Versioning configuration specified in the request is invalid.'


class IncompleteBody(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'You did not provide the number of bytes specified by the ' \
           'Content-Length HTTP header.'


class IncorrectNumberOfFilesInPostRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'POST requires exactly one file upload per request.'


class InlineDataTooLarge(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Inline data exceeds the maximum allowed size.'


class InternalError(ErrorResponse):
    _status = '500 Internal Server Error'
    _msg = 'We encountered an internal error. Please try again.'


class InvalidAccessKeyId(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The AWS Access Key Id you provided does not exist in our records.'


class InvalidArgument(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Invalid Argument.'

    def __init__(self, name, value, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, argument_name=name,
                               argument_value=value, *args, **kwargs)


class InvalidBucketName(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The specified bucket is not valid.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class InvalidBucketState(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The request is not valid with the current state of the bucket.'


class InvalidDigest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The Content-MD5 you specified was an invalid.'


class InvalidLocationConstraint(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The specified location constraint is not valid.'


class InvalidObjectState(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The operation is not valid for the current state of the object.'


class InvalidPart(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'One or more of the specified parts could not be found. The part ' \
           'might not have been uploaded, or the specified entity tag might ' \
           'not have matched the part\'s entity tag.'


class InvalidPartOrder(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The list of parts was not in ascending order.Parts list must ' \
           'specified in order by part number.'


class InvalidPayer(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'All access to this object has been disabled.'


class InvalidPolicyDocument(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The content of the form does not meet the conditions specified ' \
           'in the policy document.'


class InvalidRange(ErrorResponse):
    _status = '416 Requested Range Not Satisfiable'
    _msg = 'The requested range cannot be satisfied.'


class InvalidRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Invalid Request.'


class InvalidSecurity(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The provided security credentials are not valid.'


class InvalidSOAPRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The SOAP request body is invalid.'


class InvalidStorageClass(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The storage class you specified is not valid.'


class InvalidTargetBucketForLogging(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The target bucket for logging does not exist, is not owned by ' \
           'you, or does not have the appropriate grants for the ' \
           'log-delivery group.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, target_bucket=bucket, *args,
                               **kwargs)


class InvalidToken(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token is malformed or otherwise invalid.'


class InvalidURI(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Couldn\'t parse the specified URI.'

    def __init__(self, uri, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, uri=uri, *args, **kwargs)


class KeyTooLong(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your key is too long.'


class MalformedACLError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The XML you provided was not well-formed or did not validate ' \
           'against our published schema.'


class MalformedPOSTRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The body of your POST request is not well-formed ' \
           'multipart/form-data.'


class MalformedXML(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The XML you provided was not well-formed or did not validate ' \
           'against our published schema.'


class MaxMessageLengthExceeded(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your request was too big.'


class MaxPostPreDataLengthExceededError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your POST request fields preceding the upload file were too large.'


class MetadataTooLarge(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your metadata headers exceed the maximum allowed metadata size.'


class MethodNotAllowed(ErrorResponse):
    _status = '405 Method Not Allowed'
    _msg = 'The specified method is not allowed against this resource.'

    def __init__(self, method, resource_type, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, method=method,
                               resource_type=resource_type, *args, **kwargs)


class MissingContentLength(ErrorResponse):
    _status = '411 Length Required'
    _msg = 'You must provide the Content-Length HTTP header.'


class MissingRequestBodyError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Request body is empty.'


class MissingSecurityElement(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The SOAP 1.1 request is missing a security element.'


class MissingSecurityHeader(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your request was missing a required header.'


class NoLoggingStatusForKey(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'There is no such thing as a logging status sub-resource for a key.'


class NoSuchBucket(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified bucket does not exist.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        if not bucket:
            raise InternalError()
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class NoSuchKey(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified key does not exist.'

    def __init__(self, key, msg=None, *args, **kwargs):
        if not key:
            raise InternalError()
        ErrorResponse.__init__(self, msg, key=key, *args, **kwargs)


class NoSuchLifecycleConfiguration(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The lifecycle configuration does not exist. .'


class NoSuchUpload(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified multipart upload does not exist. The upload ID ' \
           'might be invalid, or the multipart upload might have been ' \
           'aborted or completed.'


class NoSuchVersion(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified version does not exist.'

    def __init__(self, key, version_id, msg=None, *args, **kwargs):
        if not key:
            raise InternalError()
        ErrorResponse.__init__(self, msg, key=key, version_id=version_id,
                               *args, **kwargs)


# NotImplemented is a python built-in constant.  Use S3NotImplemented instead.
class S3NotImplemented(ErrorResponse):
    _status = '501 Not Implemented'
    _msg = 'Not implemented.'
    _code = 'NotImplemented'


class NotSignedUp(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Your account is not signed up for the Amazon S3 service.'


class NotSuchBucketPolicy(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified bucket does not have a bucket policy.'


class OperationAborted(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'A conflicting conditional operation is currently in progress ' \
           'against this resource. Please try again.'


class PermanentRedirect(ErrorResponse):
    _status = '301 Moved Permanently'
    _msg = 'The bucket you are attempting to access must be addressed using ' \
           'the specified endpoint. Please send all future requests to this ' \
           'endpoint.'


class PreconditionFailed(ErrorResponse):
    _status = '412 Precondition Failed'
    _msg = 'At least one of the preconditions you specified did not hold.'


class Redirect(ErrorResponse):
    _status = '307 Moved Temporarily'
    _msg = 'Temporary redirect.'


class RestoreAlreadyInProgress(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'Object restore is already in progress.'


class RequestIsNotMultiPartContent(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Bucket POST must be of the enclosure-type multipart/form-data.'


class RequestTimeout(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your socket connection to the server was not read from or ' \
           'written to within the timeout period.'


class RequestTimeTooSkewed(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The difference between the request time and the server\'s time ' \
           'is too large.'


class RequestTorrentOfBucketError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Requesting the torrent file of a bucket is not permitted.'


class SignatureDoesNotMatch(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The request signature we calculated does not match the ' \
           'signature you provided. Check your key and signing method.'


class ServiceUnavailable(ErrorResponse):
    _status = '503 Service Unavailable'
    _msg = 'Please reduce your request rate.'


class SlowDown(ErrorResponse):
    _status = '503 Slow Down'
    _msg = 'Please reduce your request rate.'


class TemporaryRedirect(ErrorResponse):
    _status = '307 Moved Temporarily'
    _msg = 'You are being redirected to the bucket while DNS updates.'


class TokenRefreshRequired(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token must be refreshed.'


class TooManyBuckets(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'You have attempted to create more buckets than allowed.'


class UnexpectedContent(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'This request does not support content.'


class UnresolvableGrantByEmailAddress(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The e-mail address you provided does not match any account on ' \
           'record.'


class UserKeyMustBeSpecified(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The bucket POST must contain the specified field name. If it is ' \
           'specified, please check the order of the fields.'
