#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

# cab be used to generated the certificates for the go tests
# as the resulting files are in the repository, this script does not
# need to be run  each time, its purpose is to document how the keys and
# certs were created

set -e

certtool --generate-privkey --outfile testserver-key.pem


echo '
organization = "CSAF"
unit = "CSAF Distribution"
country = "DE"
cn = "csaf.test"

dns_name = "csaf.test"
dns_name = "localhost"
dns_name = "*.csaf.test"
ip_address = "127.0.0.1"
ip_address = "::1"

tls_www_server
tls_www_client
ocsp_signing_key
encryption_key
signing_key
expiration_days = 36500
'  > gnutls-certtool.testserver.template

certtool --generate-self-signed --load-privkey testserver-key.pem --outfile cert.crt --template gnutls-certtool.testserver.template --stdout | head -1

# for testing legacy code path, we use openssl's traditional mode to
# create a password protected variant after RFC 1423 that still can be read
# by https://pkg.go.dev/crypto/x509#DecryptPEMBlock. Citation:
#   Legacy PEM encryption as specified in RFC 1423 is insecure by design.
#   Since it does not authenticate the ciphertext, it is vulnerable
#   to padding oracle attacks that can let an attacker recover the plaintext.
openssl rsa -in  testserver-key.pem -out private.pem -aes256 -passout pass:qwer -traditional

echo '
organization = "CSAF Tools Development (internal)"
country = "DE"
cn = "Tester"

tls_www_client
encryption_key
signing_key

expiration_days = 36500
' > gnutls-certtool.testclientkey.template

certtool --generate-privkey --bits 3072 --outfile testclientkey.pem
certtool --generate-self-signed --load-privkey testclientkey.pem --template gnutls-certtool.testclientkey.template --outfile testclient.crt
