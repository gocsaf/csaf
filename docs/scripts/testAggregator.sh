#!/usr/bin/env bash

# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e  # to exit if a command in the script fails

# The same directory name used in the config-example file.
sudo mkdir /var/csaf_aggregator
sudo chgrp www-data /var/csaf_aggregator
sudo chmod g+ws /var/csaf_aggregator

echo
echo '=== setup nginx to serve aggregator directory on 9443'

pushd /etc/nginx/sites-enabled
sudo cp default default2
sudo sed -i -e 's/8443/9443/' -e 's/\(listen []:[]*443\)/#\1/' \
    -e 's|root /var/www/html;|root /var/csaf_aggregator/html;|' \
    default2
sudo systemctl reload nginx
popd

echo
echo '=== run aggregator'

cd ~/csaf/
sudo cp docs/examples/aggregator.toml /etc/csaf
sudo ./bin-linux-amd64/csaf_aggregator -c /etc/csaf/aggregator.toml

echo
echo '=== check aggregator for both versions ==='

for version in 2.0 2.1; do
    curl --fail --insecure --silent \
      "https://localhost:9443/.well-known/csaf-aggregator/v$version/aggregator.json" > /dev/null
done

# check symlink to authoritative version working
curl --fail --insecure --silent \
  https://localhost:9443/.well-known/csaf-aggregator/aggregator.json |
  grep -q '"aggregator_version": "2.0"'
