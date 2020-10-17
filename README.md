# Python script for saml2

This repository contains my scripts for saml2 debugging.

## decode_saml_message

This script allow to decode a saml assertion.

It displays on console the assertion and the name id from a saml response.

The saml response is passed with stdin. The saml response can be url encoded and/or base64 encoded.

It takes two arguments:

- -k or --key: to specify the private key using to decrypt the assertion.
- -l or --loglevel: to change the log level, default is WARNING.

Example:

```bash
$ cat /path/to/saml_response.txt | ./decode_saml_message.py

The SAML assertion is:
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="sdqdsdsqd" IssueInstant="2020-10-13T14:22:52.226Z" Version="2.0">...</saml:Assertion>

The name id is: mymail@example.com

$ cat /path/to/saml_response.txt | ./decode_saml_message.py -k /path/to/private_key.pem

The SAML assertion is:
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="sdqdsdsqd" IssueInstant="2020-10-13T14:22:52.226Z" Version="2.0">...</saml:Assertion>

The name id is: mymail@example.com
```
