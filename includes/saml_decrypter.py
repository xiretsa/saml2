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
import binascii
import logging
import os.path
import subprocess
import tempfile

import includes.xml_namespaces as xmlns

class SamlDecrypter:

    """
    Class to decrypt SAML element
    """

    PRIVATE_KEY_HEADER = '-----BEGIN PRIVATE KEY-----\n'
    AVAILABLE_ALGORITHM = {
        'aes128-cbc': '-aes-128-cbc',
        'rsa-1_5': '-pkcs',
        'rsa-oaep-mgf1p': '-oaep'
    }
    LOGGER = logging.getLogger(__name__)

    encrypted_data = None
    encryption_method = None

    def __init__(self, xml_element, private_key):
        self.xml_element = xml_element
        self.private_key = private_key
        if not os.path.isfile(self.private_key):
            raise RuntimeError('Private key must be an existing file')
        with open(self.private_key, 'r') as private_key:
            if not self.PRIVATE_KEY_HEADER in private_key.read():
                raise RuntimeError('The private key file must contain "{}"'.format(self.PRIVATE_KEY_HEADER))

    def decrypt_element(self):
        self.get_encrypted_data()
        session_key = self.get_encryption_key()
        self.LOGGER.info('encryption key [%s]', session_key)
        self.encryption_method = self.get_encryption_method(self.encrypted_data)
        self.LOGGER.info('encryption method for datas [%s]', self.encryption_method)
        return self.decrypt_data_with_session_key(session_key)

    def get_encrypted_data(self):
        self.encrypted_data = self.xml_element.find(xmlns.get_xml_element_fullname(xmlns.XML_ENC_URI, 'EncryptedData'))
        if self.encrypted_data is None:
            raise RuntimeError('Unable to find encrypted data')
        return self.encrypted_data

    def get_encryption_method(self, xml_element):
        encryption_method = xml_element.find(xmlns.get_xml_element_fullname(xmlns.XML_ENC_URI, 'EncryptionMethod'))
        if encryption_method is None or not 'Algorithm' in encryption_method.attrib:
            raise RuntimeError('Unable to find encryption method')
        return encryption_method.attrib['Algorithm'].replace(xmlns.XML_ENC_URI, '')

    def get_encryption_key(self):
        key_info = self.encrypted_data.find(xmlns.get_xml_element_fullname(xmlns.XML_DSIG_URI, 'KeyInfo'))
        if key_info is None:
            raise RuntimeError('Unable to find key info')
        encrypted_key = key_info.find(xmlns.get_xml_element_fullname(xmlns.XML_ENC_URI, 'EncryptedKey'))
        if encrypted_key is None:
            raise RuntimeError('Unable to find encryted key')
        encryption_method = self.get_encryption_method(encrypted_key)
        self.LOGGER.info('key encryption method [%s]', encryption_method)
        cipher_value = self.get_cipher_value(encrypted_key)
        self.LOGGER.debug('key cipher value [%s]', cipher_value)
        return self.decrypt_session_key(cipher_value, encryption_method)

    def get_cipher_value(self, encrypted_element):
        cipher_data = encrypted_element.find(xmlns.get_xml_element_fullname(xmlns.XML_ENC_URI, 'CipherData'))
        if cipher_data is None:
            raise RuntimeError('Unable to find cipher data')
        cipher_value = cipher_data.find(xmlns.get_xml_element_fullname(xmlns.XML_ENC_URI, 'CipherValue'))
        if cipher_value is None:
            raise RuntimeError('Unable to find cipher value')
        cipher_value = cipher_value.text.replace('\n', '')
        return base64.b64decode(cipher_value)

    def decrypt_session_key(self, cipher_value, encryption_method):
        self.LOGGER.info('decrypt key will use private key [%s]', self.private_key)
        with tempfile.TemporaryDirectory() as tempdir:
            with open(tempdir + '/infile', 'wb') as infile:
                infile.write(cipher_value)
            with open('/dev/null', 'w') as devnull:
                subprocess.check_call(
                    [
                        'openssl',
                        'rsautl',
                        '-decrypt',
                        '-in',
                        tempdir + '/infile',
                        '-out',
                        tempdir + '/outfile',
                        self.get_openssl_switch_from_encryption_method(encryption_method),
                        '-inkey',
                        self.private_key
                    ],
                    stdout = devnull,
                    stderr = devnull
                )
            with open(tempdir + '/outfile', 'rb') as outfile:
                binary_key = outfile.read()
                return binascii.hexlify(binary_key)

    def get_initialization_vector(self, cipher_value):
        return binascii.hexlify(cipher_value)[:16]

    def decrypt_data_with_session_key(self, session_key):
        cipher_value = self.get_cipher_value(self.encrypted_data)
        self.LOGGER.debug('data cipher value [%s]', cipher_value)
        initialization_vector = self.get_initialization_vector(cipher_value)
        self.LOGGER.info('initialization vector [%s]', initialization_vector)
        with tempfile.TemporaryDirectory() as tempdir:
            with open(tempdir + '/infile', 'wb') as infile:
                infile.write(cipher_value)
            with open('/dev/null', 'w') as devnull:
                subprocess.check_call(
                    [
                        'openssl',
                        'enc',
                        '-d',
                        self.get_openssl_switch_from_encryption_method(self.encryption_method),
                        '-in',
                        tempdir + '/infile', '-K',
                        session_key,
                        '-iv',
                        initialization_vector,
                        '-out',
                        tempdir + '/outfile',
                        '-nopad'
                    ],
                    stdout = devnull,
                    stderr = devnull
                )
            with open(tempdir + '/outfile', 'rb') as outfile:
                saml_assertion = outfile.read()[16:].decode('utf-8', 'ignore')
                return saml_assertion[:saml_assertion.rfind('>') + 1]

    def get_openssl_switch_from_encryption_method(self, encryption_method):
        if not encryption_method in self.AVAILABLE_ALGORITHM:
            raise KeyError('Encryption method [{}] is unknown'.format(encryption_method))
        return self.AVAILABLE_ALGORITHM[encryption_method]
