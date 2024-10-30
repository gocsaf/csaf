#!/usr/bin/env bash

# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e  # to exit if a command in the script fails

echo '==== run checker (twice)'
cd ~/csaf

./bin-linux-amd64/csaf_checker -f html -o ../checker-results.html --insecure \
  --client_cert ~/devca1/testclient1.crt \
  --client_key ~/devca1/testclient1-key.pem \
  --verbose --insecure localhost

cat ../checker-results.html

./bin-linux-amd64/csaf_checker -o ../checker-results-no-clientcert.json \
  --insecure --verbose localhost
