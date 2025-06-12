#!/usr/bin/env bash
#
# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

# This script adds a new server block with the given DNS-Record and ajdust the "/etc/hosts" to
# set the DNS-Record for the localhost for testing.

set -e

sudo touch /etc/nginx/sites-available/DNSConfig
echo "
    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;

        ssl_certificate  '${SSL_CERTIFICATE}'; # e.g. ssl_certificate /etc/ssl/csaf/bundle.crt
        ssl_certificate_key '${SSL_CERTIFICATE_KEY}'; # e.g. ssl_certificate_key /etc/ssl/csaf/testserver-key.pem;

        root /var/www/html;

        server_name ${DNS_NAME}; # e.g. server_name csaf.data.security.domain.tld;

        location = / {
                try_files /.well-known/csaf/provider-metadata.json =404;
                # allow others web applications to get the static information
                add_header Access-Control-Allow-Origin "*";
        }

        access_log /var/log/nginx/dns-domain_access.log;
        error_log /var/log/nginx/dns-domain_error.log;
}
" | sudo tee -a /etc/nginx/sites-available/DNSConfig

sudo ln -s /etc/nginx/sites-available/DNSConfig /etc/nginx/sites-enabled/

echo "
    127.0.0.1 $DNS_NAME
" | sudo tee -a /etc/hosts
