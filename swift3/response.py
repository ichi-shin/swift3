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
from UserDict import DictMixin

from swift.common.swob import Response, HTTPException, HeaderKeyDict

from swift3.utils import snake_to_camel, get_owner_from_acl
from swift3.etree import Element, SubElement, tostring


def _resp_bucket_owner_property():
    key = 'x-container-meta-[swift3]-owner'

    def getter(self):
        if key in self.swift3_headers:
            return self.swift3_headers[key]
        else:
            return get_owner_from_acl(self.sw_headers)

    return property(getter, doc='Get the bucket owner property')


def _resp_swift3_property(resource, name, default=None):
    key = 'x-%s-meta-[swift3]-%s' % (resource, name)

    def getter(self):
        return self.swift3_headers.get(key, default)

    return property(getter, doc='Get the %s %s property' % (resource, name))


class S3Response(Response):
    bucket_owner = _resp_bucket_owner_property()
    bucket_timestamp = _resp_swift3_property('container', 'timestamp')
    object_owner = _resp_swift3_property('object', 'owner', 'undefined')
    object_timestamp = _resp_swift3_property('object', 'timestamp')
    versioned = _resp_swift3_property('object', 'versioned')
    versioning_status = _resp_swift3_property('container', 'versioning-status')
    delete_marker = _resp_swift3_property('object', 'delete-marker')
    missing_meta = _resp_swift3_property('object', 'missing-meta')

    def __init__(self, s3_req, sw_req, sw_resp):
        if sw_resp.app_iter:
            body = None
            app_iter = sw_resp.app_iter
        else:
            body = sw_resp.body
            app_iter = None

        self.swift3_headers = HeaderKeyDict()
        self.sw_headers = HeaderKeyDict()

        headers = HeaderKeyDict()
        for key, val in sw_resp.headers.iteritems():
            _key = key.lower()
            if "[swift3]" in _key:
                self.swift3_headers[_key] = val
                if _key == 'x-object-meta-[swift3]-versioned' and \
                        'x-object-meta-[swift3]-timestamp' in sw_resp.headers:
                    from swift3.request import VersionId
                    ts_key = 'x-object-meta-[swift3]-timestamp'
                    headers['x-amz-version-id'] = \
                        str(VersionId(sw_resp.headers[ts_key]))
                if _key == 'x-object-meta-[swift3]-delete-marker':
                    headers['x-amz-delete-marker'] = val
                if _key == 'x-object-meta-[swift3]-missing-meta':
                    headers['x-amz-missing-meta'] = val
            elif _key.startswith('x-object-meta-'):
                headers['x-amz-meta-' + key[14:]] = val
            elif _key in ('content-length', 'content-type',
                          'content-range', 'content-encoding',
                          'etag', 'last-modified'):
                headers[key] = val
            else:
                self.sw_headers[key] = val

        Response.__init__(self, status=sw_resp.status, headers=headers,
                          request=sw_req, body=body, app_iter=app_iter,
                          conditional_response=sw_resp.conditional_response)
        self.environ.update(sw_resp.environ)
        self.s3_req = s3_req

    @property
    def x_timestamp(self):
        return self.sw_headers['x-timestamp']


class S3ErrorResponse(HTTPException):
    def __init__(self, msg=None, *args, **kwargs):
        if msg:
            self._msg = msg

        self.info = kwargs.copy()
        for reserved_key in ('headers', 'body'):
            if self.info.get(reserved_key):
                del(self.info[reserved_key])

        HTTPException.__init__(self, status=self._status,
                               app_iter=self._body_iter(),
                               content_type='text/xml', *args, **kwargs)

    def _body_iter(self):
        error_elem = Element('Error', use_s3ns=False)
        SubElement(error_elem, 'Code').text = self.__class__.__name__
        SubElement(error_elem, 'Message').text = self._msg
        if 'swift.trans_id' in self.environ:
            request_id = self.environ['swift.trans_id']
            SubElement(error_elem, 'RequestId').text = request_id

        self._dict_to_etree(error_elem, self.info)

        yield tostring(error_elem)

    def _dict_to_etree(self, parent, d):
        for key, value in d.items():
            tag = re.sub('\W', '', snake_to_camel(key))
            # TODO: any other dict class?
            if isinstance(value, (dict, DictMixin)):
                elem = SubElement(parent, tag)
                self._dict_to_etree(elem, value)
            else:
                SubElement(parent, tag).text = value


class AccessDenied(S3ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Access Denied.'


class AccountProblem(S3ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'There is a problem with your AWS account that prevents the ' \
           'operation from completing successfully. Please use .'


class AmbiguousGrantByEmailAddress(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The e-mail address you provided is associated with more than ' \
           'one account.'


class BadDigest(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The Content-MD5 you specified did not match what we received.'


class BucketAlreadyExists(S3ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The requested bucket name is not available. The bucket ' \
           'namespace is shared by all users of the system. Please select a ' \
           'different name and try again.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        S3ErrorResponse.__init__(self, msg, bucket_name=bucket, *args,
                                 **kwargs)


class BucketAlreadyOwnedByYou(S3ErrorResponse):
    _status = '409 Conflict'
    _msg = 'Your previous request to create the named bucket succeeded and ' \
           'you already own it. You get this error in all AWS regions ' \
           'except US Standard, us-east-1. In us-east-1 region, you will ' \
           'get 200 OK, but it is no-op (if bucket exists it Amazon S3 will ' \
           'not do anything).'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        S3ErrorResponse.__init__(self, msg, bucket_name=bucket, *args,
                                 **kwargs)


class BucketNotEmpty(S3ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The bucket you tried to delete is not empty.'


class CredentialsNotSupported(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'This request does not support credentials.'


class CrossLocationLoggingProhibited(S3ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Cross location logging not allowed. Buckets in one geographic ' \
           'location cannot log information to a bucket in another ' \
           'location.'


class EntityTooSmall(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your proposed upload is smaller than the minimum allowed object ' \
           'size.'


class EntityTooLarge(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your proposed upload exceeds the maximum allowed object size.'


class ExpiredToken(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token has expired.'


class IllegalVersioningConfigurationException(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Indicates that the Versioning configuration specified in the ' \
           'request is invalid.'


class IncompleteBody(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'You did not provide the number of bytes specified by the ' \
           'Content-Length HTTP header.'


class IncorrectNumberOfFilesInPostRequest(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'POST requires exactly one file upload per request.'


class InlineDataTooLarge(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Inline data exceeds the maximum allowed size.'


class InternalError(S3ErrorResponse):
    _status = '500 Internal Server Error'
    _msg = 'We encountered an internal error. Please try again.'


class InvalidAccessKeyId(S3ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The AWS Access Key Id you provided does not exist in our ' \
           'records.'


class InvalidArgument(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Invalid Argument.'

    def __init__(self, name, value, msg=None, *args, **kwargs):
        S3ErrorResponse.__init__(self, msg, argument_name=name,
                                 argument_value=value, *args, **kwargs)


class InvalidBucketName(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The specified bucket is not valid.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        S3ErrorResponse.__init__(self, msg, bucket_name=bucket, *args,
                                 **kwargs)


class InvalidBucketState(S3ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The request is not valid with the current state of the bucket.'


class InvalidDigest(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The Content-MD5 you specified was an invalid.'


class InvalidLocationConstraint(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The specified location constraint is not valid. For more ' \
           'information about Regions, see . .'


class InvalidObjectState(S3ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The operation is not valid for the current state of the object.'


class InvalidPart(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'One or more of the specified parts could not be found. The part ' \
           'might not have been uploaded, or the specified entity tag might ' \
           'not have matched the part\'s entity tag.'


class InvalidPartOrder(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The list of parts was not in ascending order.Parts list must ' \
           'specified in order by part number.'


class InvalidPayer(S3ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'All access to this object has been disabled.'


class InvalidPolicyDocument(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The content of the form does not meet the conditions specified ' \
           'in the policy document.'


class InvalidRange(S3ErrorResponse):
    _status = '416 Requested Range Not Satisfiable'
    _msg = 'The requested range cannot be satisfied.'


class InvalidRequest(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'SOAP requests must be made over an HTTPS connection.'


class InvalidSecurity(S3ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The provided security credentials are not valid.'


class InvalidSOAPRequest(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The SOAP request body is invalid.'


class InvalidStorageClass(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The storage class you specified is not valid.'


class InvalidTargetBucketForLogging(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The target bucket for logging does not exist, is not owned by ' \
           'you, or does not have the appropriate grants for the ' \
           'log-delivery group. .'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        S3ErrorResponse.__init__(self, msg, target_bucket=bucket, *args,
                                 **kwargs)


class InvalidToken(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token is malformed or otherwise invalid.'


class InvalidURI(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Couldn\'t parse the specified URI.'

    def __init__(self, uri, msg=None, *args, **kwargs):
        S3ErrorResponse.__init__(self, msg, URI=uri, *args, **kwargs)


class KeyTooLong(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your key is too long.'


class MalformedACLError(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The XML you provided was not well-formed or did not validate ' \
           'against our published schema.'


class MalformedPOSTRequest(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The body of your POST request is not well-formed ' \
           'multipart/form-data.'


class MalformedXML(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'This happens when the user sends a malformed xml (xml that ' \
           'doesn\'t conform to the published xsd) for the configuration. ' \
           'The error message is, "The XML you provided was not well-formed ' \
           'or did not validate against our published schema." .'


class MaxMessageLengthExceeded(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your request was too big.'


class MaxPostPreDataLengthExceededError(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your POST request fields preceding the upload file were too ' \
           'large.'


class MetadataTooLarge(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your metadata headers exceed the maximum allowed metadata size.'


class MethodNotAllowed(S3ErrorResponse):
    _status = '405 Method Not Allowed'
    _msg = 'The specified method is not allowed against this resource.'

    def __init__(self, method=None, msg=None, *args, **kwargs):
        S3ErrorResponse.__init__(self, msg, method=method, *args,
                                 **kwargs)


class MissingContentLength(S3ErrorResponse):
    _status = '411 Length Required'
    _msg = 'You must provide the Content-Length HTTP header.'


class MissingRequestBodyError(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'This happens when the user sends an empty xml document as a ' \
           'request. The error message is, "Request body is empty." .'


class MissingSecurityElement(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The SOAP 1.1 request is missing a security element.'


class MissingSecurityHeader(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your request was missing a required header.'


class NoLoggingStatusForKey(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'There is no such thing as a logging status sub-resource for a ' \
           'key.'


class NoSuchBucket(S3ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified bucket does not exist.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        if not bucket:
            raise InternalError()
        S3ErrorResponse.__init__(self, msg, bucket_name=bucket, *args,
                                 **kwargs)


class NoSuchKey(S3ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified key does not exist.'

    def __init__(self, key, msg=None, *args, **kwargs):
        if not key:
            raise InternalError()
        S3ErrorResponse.__init__(self, msg, key=key, *args, **kwargs)


class NoSuchLifecycleConfiguration(S3ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The lifecycle configuration does not exist. .'


class NoSuchUpload(S3ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified multipart upload does not exist. The upload ID ' \
           'might be invalid, or the multipart upload might have been ' \
           'aborted or completed.'


class NoSuchVersion(S3ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified version does not exist.'

    def __init__(self, key, version_id, msg=None, *args, **kwargs):
        if not key:
            raise InternalError()
        S3ErrorResponse.__init__(self, msg, key=key, version_id=version_id,
                                 *args, **kwargs)


class NotImplemented(S3ErrorResponse):
    _status = '501 Not Implemented'
    _msg = 'A header you provided implies functionality that is not ' \
           'implemented.'


class NotSignedUp(S3ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Your account is not signed up for the Amazon S3 service. You ' \
           'must sign up before you can use Amazon S3. You can sign up at ' \
           'the following URL: http://aws.amazon.com/s3.'


class NotSuchBucketPolicy(S3ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified bucket does not have a bucket policy.'


class OperationAborted(S3ErrorResponse):
    _status = '409 Conflict'
    _msg = 'A conflicting conditional operation is currently in progress ' \
           'against this resource. Please try again.'


class PermanentRedirect(S3ErrorResponse):
    _status = '301 Moved Permanently'
    _msg = 'The bucket you are attempting to access must be addressed using ' \
           'the specified endpoint. Please send all future requests to this ' \
           'endpoint.'


class PreconditionFailed(S3ErrorResponse):
    _status = '412 Precondition Failed'
    _msg = 'At least one of the preconditions you specified did not hold.'


class Redirect(S3ErrorResponse):
    _status = '307 Moved Temporarily'
    _msg = 'Temporary redirect.'


class RestoreAlreadyInProgress(S3ErrorResponse):
    _status = '409 Conflict'
    _msg = 'Object restore is already in progress.'


class RequestIsNotMultiPartContent(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Bucket POST must be of the enclosure-type multipart/form-data.'


class RequestTimeout(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your socket connection to the server was not read from or ' \
           'written to within the timeout period.'


class RequestTimeTooSkewed(S3ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The difference between the request time and the server\'s time ' \
           'is too large.'


class RequestTorrentOfBucketError(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Requesting the torrent file of a bucket is not permitted.'


class SignatureDoesNotMatch(S3ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The request signature we calculated does not match the ' \
           'signature you provided. Check your AWS Secret Access Key and ' \
           'signing method. For more information, see and for details.'


class ServiceUnavailable(S3ErrorResponse):
    _status = '503 Service Unavailable'
    _msg = 'Please reduce your request rate.'


class SlowDown(S3ErrorResponse):
    _status = '503 Slow Down'
    _msg = 'Please reduce your request rate.'


class TemporaryRedirect(S3ErrorResponse):
    _status = '307 Moved Temporarily'
    _msg = 'You are being redirected to the bucket while DNS updates.'


class TokenRefreshRequired(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token must be refreshed.'


class TooManyBuckets(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'You have attempted to create more buckets than allowed.'


class UnexpectedContent(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'This request does not support content.'


class UnresolvableGrantByEmailAddress(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The e-mail address you provided does not match any account on ' \
           'record.'


class UserKeyMustBeSpecified(S3ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The bucket POST must contain the specified field name. If it is ' \
           'specified, please check the order of the fields.'
