#!/usr/bin/env bash
#
# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

# This script sets up the csaf_provider and writes the required nginx configurations.
# It creates the initial folders and uploads some example files to the csaf_provider with the help of `uploadToProvider.sh`

set -e

sudo chgrp -R www-data  /var/www
sudo chmod -R g+ws  /var/www

export NGINX_CONFIG_PATH=/etc/nginx/sites-available/default
export DNS_NAME=csaf.data.security.test

sudo cp /usr/share/doc/fcgiwrap/examples/nginx.conf /etc/nginx/fcgiwrap.conf

echo '
# Include this file on your nginx.conf to support debian cgi-bin scripts using
# fcgiwrap
location /cgi-bin/ {
  # Disable gzip (it makes scripts feel slower since they have to complete
  # before getting gzipped)
  gzip off;

  # Set the root to /usr/lib (inside this location this means that we are
  # giving access to the files under /usr/lib/cgi-bin)
  root  /usr/lib;

  # Fastcgi socket
  fastcgi_pass  unix:/var/run/fcgiwrap.socket;

  # Fastcgi parameters, include the standard ones
  include /etc/nginx/fastcgi_params;

  fastcgi_split_path_info ^(.+\.go)(.*)$;

  # Adjust non standard parameters (SCRIPT_FILENAME)
  fastcgi_param SCRIPT_FILENAME  /usr/lib$fastcgi_script_name;
  fastcgi_param PATH_INFO $fastcgi_path_info;

  fastcgi_param CSAF_CONFIG /etc/csaf/config.toml;

  fastcgi_param SSL_CLIENT_VERIFY $ssl_client_verify;
  fastcgi_param SSL_CLIENT_S_DN $ssl_client_s_dn;
  fastcgi_param SSL_CLIENT_I_DN $ssl_client_i_dn;
}
' | sudo tee /etc/nginx/fcgiwrap.conf

sudo sed -i "/^server {/a\        include fcgiwrap.conf;" $NGINX_CONFIG_PATH

echo "
        # For atomic directory switches
        disable_symlinks off;

        # directory listings
        autoindex on;

        # allow others web applications to get the static information
        add_header Access-Control-Allow-Origin "*";
" > locationConfig.txt
sudo sed -i "/^\s*location \/ {/r locationConfig.txt" $NGINX_CONFIG_PATH # Insert config inside location{}
./DNSConfigForItest.sh
sudo systemctl reload nginx

# assuming that we are in a checked out version in the docs/scripts directory
# and we want to build the version that is currently checked out
pushd ../..

export PATH=$PATH:/usr/local/go/bin
make build_linux
# Place the binary under the corresponding path.
sudo mkdir -p /usr/lib/cgi-bin/
sudo chgrp www-data /usr/lib/cgi-bin/
sudo chmod o-rwx /usr/lib/cgi-bin/
sudo cp bin-linux-amd64/csaf_provider /usr/lib/cgi-bin/csaf_provider.go

sudo mkdir /etc/csaf/
sudo chgrp www-data /etc/csaf/
sudo chmod g+s,o-rwx /etc/csaf/
sudo touch /etc/csaf/config.toml
sudo chgrp www-data /etc/csaf/config.toml
sudo chmod g+r,o-rwx /etc/csaf/config.toml

sudo cp docs/test-keys/*.asc /etc/csaf/
sudo chgrp www-data /etc/csaf/private.asc
sudo chmod o-rwx  /etc/csaf/private.asc

# Configuration file
echo '
# upload_signature = true
openpgp_private_key = "/etc/csaf/private.asc"
openpgp_public_key = "/etc/csaf/public.asc"
#tlps = ["green", "red"]
canonical_url_prefix = "https://localhost:8443"
categories = ["Example Company Product A", "expr:document.lang"]
create_service_document = true
#no_passphrase = true
' | sudo tee --append /etc/csaf/config.toml

# Create the Folders
curl https://localhost:8443/cgi-bin/csaf_provider.go/api/create --cert-type p12 --cert ~/devca1/testclient1.p12 --insecure

popd

# Setup validation service
./setupValidationService.sh

# Disable exit for the next error as these is expected.
set +e

# Wait for the service to be started
echo
echo === Try to reach the validator service ten times, up to nine fails are ok
for ((i = 1; i <= 10; i++)); do
 if [ $(curl -IL http://localhost:8082/api/v1/tests | grep -c HTTP ) != "0" ]; then
 break
 fi
 sleep 3
done

if [ $i == 11 ]; then
    echo Could not connect to validation service!
    exit 1
fi

# Upload files
./uploadToProvider.sh

# Test resolving DNS record
curl https://$DNS_NAME --insecure

./testChecker.sh
