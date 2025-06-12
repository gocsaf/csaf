# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e

pushd ~/${FOLDERNAME}

certtool --generate-privkey --outfile testserver-key.pem

echo '
organization = "'${ORGANAME}'"
country = DE
cn = "Service Testing"

tls_www_server
signing_key
encryption_key
non_repudiation

dns_name = "*.local"
dns_name = "localhost"

serial = 010
expiration_days = 50
' > gnutls-certtool.testserver.template

certtool --generate-certificate --load-privkey testserver-key.pem --outfile testserver.crt --load-ca-certificate rootca-cert.pem --load-ca-privkey rootca-key.pem --template gnutls-certtool.testserver.template --stdout | head -1

cat testserver.crt rootca-cert.pem >bundle.crt

export SSL_CERTIFICATE=$(
echo "$PWD/bundle.crt"
)
export SSL_CERTIFICATE_KEY=$(
echo "$PWD/testserver-key.pem"
)

popd
