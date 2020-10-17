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

XML_ENC_URI = 'http://www.w3.org/2001/04/xmlenc#'
XML_ASSERTION_URI = 'urn:oasis:names:tc:SAML:2.0:assertion'
XML_DSIG_URI = 'http://www.w3.org/2000/09/xmldsig#'

def get_xml_element_fullname(namespace, tag):
    return '{{{ns}}}{tag}'.format(ns = namespace, tag = tag)
