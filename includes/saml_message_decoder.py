#
# Copyright (C) 2020 Pierre Faucquenoy
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import base64
import logging
import re
import urllib.parse
import zlib

import includes.xml_namespaces as xmlns

from .saml_decrypter import SamlDecrypter
from lxml import etree

class SamlMessageDecoder:

    """
    Class to store a Saml message and decode it
    """

    BASE64_PATTERN = '^[A-Za-z0-9+/]+=*$'
    GZIP_HEADER = '\x1f\x8b\x08'
    LOGGER = logging.getLogger(__name__)

    def __init__(self, message, private_key = None):
        self.original_message = message
        self.private_key = private_key
        self.decoded_message = None
        self.xml_message = None
        self.decode_message()
        self.load_as_xml()

    def set_private_key(self, private_key):
        self.private_key = private_key

    def decode_message(self):
        decoded_message = self.original_message
        if '%' in decoded_message:
            decoded_message = self.url_decode_message(decoded_message)
        if self.is_base64_encoded(decoded_message):
            decoded_message = self.base64_decode_message(decoded_message)
        if self.is_compressed(decoded_message):
            decoded_message = self.decompress_message(decoded_message)
        try:
            self.decoded_message = decoded_message.decode('utf-8')
        except(AttributeError):
            self.decoded_message = decoded_message
        self.LOGGER.debug('decoded message [%s]', self.decoded_message)

    def url_decode_message(self, message):
        self.LOGGER.info('decode message from url encoding')
        return urllib.parse.unquote_plus(message)

    def is_base64_encoded(self, message):
        base64_pattern = re.compile(self.BASE64_PATTERN)
        is_base64 = False
        if base64_pattern.match(message):
            is_base64 = True
        self.LOGGER.info('message is base64 encoded [%s]', is_base64)
        return is_base64

    def base64_decode_message(self, message):
        return base64.b64decode(message)

    def is_compressed(self, message):
        is_compressed = False
        if str(message).startswith(self.GZIP_HEADER):
            is_compressed = True
        self.LOGGER.info('message is compressed [%s]', is_compressed)
        return is_compressed

    def decompress_message(self, message):
        return zlib.decompress(message, -15)

    def get_assertion_to_string(self):
        return etree.tostring(self.get_assertion())

    def get_assertion(self):
        assertion = self.xml_message.find(xmlns.get_xml_element_fullname(xmlns.XML_ASSERTION_URI, 'Assertion'))
        if assertion is not None:
            self.LOGGER.info('assertion is not encrypted')
            return assertion
        assertion = self.xml_message.find(xmlns.get_xml_element_fullname(xmlns.XML_ASSERTION_URI, 'EncryptedAssertion'))
        if assertion is not None:
            self.LOGGER.info('assertion is encrypted')
            return etree.fromstring(self.decrypt_assertion(assertion))
        self.LOGGER.error('Payload does not contain assertion')

    def get_name_id(self):
        assertion = self.get_assertion()
        subject = assertion.find(xmlns.get_xml_element_fullname(xmlns.XML_ASSERTION_URI, 'Subject'))
        if subject is None:
            self.LOGGER.error('Unable to find subject')
            return
        name_id = subject.find(xmlns.get_xml_element_fullname(xmlns.XML_ASSERTION_URI, 'NameID'))
        if name_id is None:
            self.LOGGER.error('Unable to find name id')
            return
        self.LOGGER.info('name id found [%s]', name_id.text)
        return name_id.text

    def decrypt_assertion(self, assertion):
        if self.private_key is None:
            self.LOGGER.error('A private key is needed to decrypt the SAML assertion')
            return
        saml_decrypter = SamlDecrypter(assertion, self.private_key)
        return saml_decrypter.decrypt_element()

    def load_as_xml(self):
        self.xml_message = etree.fromstring(self.decoded_message)

    def get_decoded_message(self):
        return self.decoded_message
