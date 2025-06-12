#!/usr/bin/env bash

# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e

mkdir -p ~/${FOLDERNAME}
cd ~/${FOLDERNAME}

certtool --generate-privkey --outfile rootca-key.pem

echo '
organization = "'${ORGANAME}'"
country = DE
cn = "Tester"

ca
cert_signing_key
crl_signing_key

serial = 001
expiration_days = 100
' >gnutls-certtool.rootca.template

certtool --generate-self-signed --load-privkey rootca-key.pem --outfile rootca-cert.pem --template gnutls-certtool.rootca.template --stdout | head -1
