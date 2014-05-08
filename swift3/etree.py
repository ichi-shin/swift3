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

import lxml.etree
from urllib import quote, unquote
from pkg_resources import resource_stream

from swift3 import utils

XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'
XMLNS_XSD = 'http://www.w3.org/2001/XMLSchema'


# Normalize input XML for validation
def _normarlize_xml(xml, root_tag):
    # Add S3 namespace for XMLSchema validation
    for e in xml.iter():
        if not isinstance(e.tag, str):
            # Probably, e is a comment.
            continue

        if None in e.nsmap:
            # Replace no prefix namespace with S3 URL.  This looks strange
            # behavior but what AWS S3 actually does...
            if e.tag.startswith('{%s}' % e.nsmap[None]):
                e.tag = '{%s}%s' % (XMLNS_S3, e.tag[len(e.nsmap[None]) + 2:])
        else:
            e.tag = '{%s}%s' % (XMLNS_S3, e.tag)

    tag = '{%s}%s' % (XMLNS_S3, root_tag)
    nsmap = xml.nsmap.copy()
    nsmap.update({None: XMLNS_S3})

    # AWS S3 doesn't return error against a wrong root tag name
    root = lxml.etree.Element(tag, attrib=xml.attrib, nsmap=nsmap)
    root.text = xml.text
    root.extend(xml.getchildren())

    return root


def fromstring(text, root_tag):
    elem = lxml.etree.fromstring(text)
    elem = _normarlize_xml(elem, root_tag)

    # validate XML
    s3_xsd = resource_stream(__name__, 'AmazonS3.xsd')
    xmlschema = lxml.etree.XMLSchema(file=s3_xsd)
    xmlschema.assertValid(elem)

    return Element(elem=elem)


def tostring(tree):
    pretty_print = utils.PRETTY_PRINT_XML

    return lxml.etree.tostring(tree._element, xml_declaration=True,
                               encoding='UTF-8', pretty_print=pretty_print)


class ElementBase(object):
    def __init__(self, elem, encoding_type=None):
        self._element = elem
        self.encoding_type = encoding_type

    def find(self, path):
        def _add_namespace(tag):
            if tag.isalnum():
                return '{%s}%s' % (XMLNS_S3, tag)
            else:
                return tag

        parts = [_add_namespace(part) for part in path.split('/')]
        path = '/'.join(parts)
        elem = self._element.find(path)
        if elem is None:
            return None

        return SubElement(self, elem=elem)

    def __iter__(self):
        return self._element.__iter__()

    def iterchildren(self, tag=None):
        if tag is not None:
            tag = '{%s}%s' % (XMLNS_S3, tag)

        for elem in self._element.iterchildren(tag):
            yield SubElement(self, elem=elem)

    def _get_attr_key(self, key):
        if '{' not in key and ':' in key:
            prefix, name = key.split(':', 1)
            if prefix in self.nsmap:
                return '{%s}%s' % (self.nsmap[prefix], name)

        return key

    def get(self, key, default=None):
        return self._element.get(self._get_attr_key(key), default)

    def set(self, key, value):
        return self._element.set(self._get_attr_key(key), value)

    @property
    def nsmap(self):
        return self._element.nsmap

    @property
    def tag(self):
        if self._element.tag.startswith('{%s}' % XMLNS_S3):
            # Remvoe S3 namespace
            return self._element.tag[len(XMLNS_S3) + 2:]
        else:
            return self._element.tag

    @property
    def text(self):
        value = self._element.text
        if value is None:
            return None

        if self.encoding_type == 'url':
            return unquote(value)

        return utils.utf8encode(value)

    @text.setter
    def text(self, value):
        blacklist = ['LastModified', 'ID', 'DisplayName', 'Initiated']

        try:
            if value is None:
                self._element.text = None
            elif isinstance(value, basestring) and value == '':
                self._element.text = None
            else:
                if not isinstance(value, basestring):
                    value = str(value)

                if self.encoding_type == 'url' and self.tag not in blacklist:
                    self._element.text = quote(value)
                else:
                    self._element.text = utils.utf8decode(value)
        except ValueError:
            # We tried to set an invalid string for XML
            self._element.text = ''


class Element(ElementBase):
    def __init__(self, tag=None, attrib=None, nsmap=None, encoding_type=None,
                 elem=None, use_s3ns=True):
        if elem is None:
            if use_s3ns:
                nsmap = nsmap or {}
                nsmap.update({None: XMLNS_S3})
            elem = lxml.etree.Element(tag, attrib, nsmap)
        ElementBase.__init__(self, elem, encoding_type)


class SubElement(ElementBase):
    def __init__(self, parent=None, tag=None, attrib=None, nsmap=None,
                 elem=None):
        if elem is None:
            elem = lxml.etree.SubElement(parent._element, tag, attrib, nsmap)
        ElementBase.__init__(self, elem, parent.encoding_type)
