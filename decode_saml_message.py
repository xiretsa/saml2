#!/usr/bin/env python3
# coding: utf-8

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

import getopt
import logging
import logging.config
import sys

from includes.saml_message_decoder import SamlMessageDecoder

def usage():
    print('usage: {} [-h|--help] [-k|--key=PRIVATE_KEY_PATH]'.format(sys.argv[0]))
    print('Decode a SAML message')
    print('the message is read from stdin')
    print()
    print('  [-h, --help]                                    : Display this help')
    print('  [-k PRIVATE_KEY_PATH, --key=PRIVATE_KEY_PATH]   : Private key to decrypt element')
    print('  [-l LOG_LEVEL, --loglevel=LOG_LEVEL]            : Log level from python logging (https://docs.python.org/3/library/logging.html#levels)')
    sys.exit(1)

def configure_logging(log_level):
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s [%(levelname)s] [%(name)s] %(message)s'
            },
        },
        'handlers': {
            'default_handler': {
                'class': 'logging.StreamHandler',
                'level': 'DEBUG',
                'formatter': 'standard',
                'stream': sys.stdout
            },
        },
        'loggers': {
            '': {
                'handlers': ['default_handler'],
                'level': log_level,
                'propagate': False
            }
        }
    }
    logging.config.dictConfig(logging_config)

def main(argv):
    private_key = None
    log_level = 'WARNING'
    try:
        opts, args = getopt.getopt(argv, "hk:l:", ["help", "key=", "loglevel="])
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
        elif opt in ('-k', '--key'):
            private_key = arg
        elif opt in ('-l', '--loglevel'):
            log_level = arg.upper()
    configure_logging(log_level)
    logger = logging.getLogger(__name__)
    saml_decoder = SamlMessageDecoder(sys.stdin.read(), private_key)
    print('The SAML assertion is:\n{}'.format(saml_decoder.get_assertion_to_string()))
    print()
    print('The name id is: {}'.format(saml_decoder.get_name_id()))

main(sys.argv[1:])
