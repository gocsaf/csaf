#!/usr/bin/env bash

# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e  # to exit if a command in the script fails

cd ~/csaf

echo
echo '==== run downloader (1)'

mkdir ~/downloaded1

./bin-linux-amd64/csaf_downloader --directory ../downloaded1 \
  --rate 4.1 --insecure localhost

echo
echo '==== this was downloaded (1)'
pushd ~/downloaded1
find .
popd

echo
echo '==== run downloader for CSAF 2.0 (1a)'

mkdir ~/downloaded1-2.0

./bin-linux-amd64/csaf_downloader --directory ../downloaded1-2.0 \
  --rate 4.1 --insecure --csaf_version=2.0 localhost

echo
echo '==== run downloader for CSAF 2.1 (1b)'

mkdir ~/downloaded1-2.1

./bin-linux-amd64/csaf_downloader --directory ../downloaded1-2.1 \
  --rate 4.1 --insecure --csaf_version=2.1 localhost

echo
echo '==== this was downloaded (1a, 1b)'

pushd ~
find downloaded1-2.0 downloaded1-2.1
popd

echo
echo '==== run downloader (2)'

mkdir ~/downloaded2

./bin-linux-amd64/csaf_downloader --directory ../downloaded2 \
  --insecure https://localhost:9443/.well-known/csaf-aggregator/v2.0/local-dev-provider2/provider-metadata.json

echo
echo '==== this was downloaded (2)'
pushd ~/downloaded2
find .
popd

echo
echo '=== run downloader from the CSAF 2.1 mirror (2b)'

mkdir ~/downloaded2-2.1

./bin-linux-amd64/csaf_downloader --directory ../downloaded2-2.1 \
  --insecure https://localhost:9443/.well-known/csaf-aggregator/v2.1/local-dev-provider2-v21/provider-metadata.json

echo
echo '==== this was downloaded (2b)'
pushd ~/downloaded2-2.1
find .
popd
