# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

# This script generates webserver cert that is signed with the generated root CA.
# It sets the right nginx configurations for serving TLS connections.
# FOLDERNAME and ORGANAME variables must be set.
# FOLDERNAME: Where to store the CAs and keys.
# ORGANAME: The organization name used in the CA template.
# Usage Example: env FOLDERNAME=devca1 ORGANAME="CSAF Tools Development (internal)" ./TLSConfigsForITest.sh

set -e

NGINX_CONFIG_PATH=/etc/nginx/sites-available/default

cd ~/csaf/docs/scripts/
## Create Root CA
./createRootCAForITest.sh

## Create webserver cert
source ./createWebserverCertForITest.sh

# Configure nginx
echo '
        listen 443 ssl default_server; # ipv4
        listen [::]:443 ssl http2 default_server;  # ipv6

        ssl_certificate  '${SSL_CERTIFICATE}'; # e.g. ssl_certificate /etc/ssl/csaf/bundle.crt
        ssl_certificate_key '${SSL_CERTIFICATE_KEY}'; # e.g. ssl_certificate_key /etc/ssl/csaf/testserver-key.pem;

        ssl_protocols TLSv1.2 TLSv1.3;
' > ~/${FOLDERNAME}/TLSConfigs.txt

# a second listener port for testing setup where someone wants to tunnel access
# to an unpriviledged port and still have the same access url
echo '
        listen 8443 ssl default_server; # ipv4
        listen [::]:8443 ssl http2 default_server;  # ipv6
' > ~/${FOLDERNAME}/TLS8443Configs.txt

sudo cp $NGINX_CONFIG_PATH $NGINX_CONFIG_PATH.org
sudo sed -i "/^server {/r ${HOME}/${FOLDERNAME}/TLSConfigs.txt" $NGINX_CONFIG_PATH
sudo sed -i "/^server {/r ${HOME}/${FOLDERNAME}/TLS8443Configs.txt" $NGINX_CONFIG_PATH
sudo sed -i "/^\s*listen.*80/d" $NGINX_CONFIG_PATH # Remove configs for listinig on port 80
sudo systemctl start nginx
sudo systemctl reload nginx
