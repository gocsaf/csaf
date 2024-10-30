#!/usr/bin/env bash
set -e

# This script prepares a naked Ubuntu LTS amd64
# for the csaf integration tests
# by installing the required packages.

apt update
apt install -y make bash curl gnupg sed tar git nginx fcgiwrap gnutls-bin

# Install Go from binary distribution
latest_go="$(curl https://go.dev/VERSION\?m=text| head -1).linux-amd64.tar.gz"
curl -O https://dl.google.com/go/$latest_go
rm -rf /usr/local/go # be sure that we do not have an old installation
tar -C /usr/local -xzf $latest_go

# Install a current Node.js version from nodesource
# as needed for https://github.com/secvisogram/csaf-validator-service
# Instructions from
#  https://github.com/nodesource/distributions/blob/master/README.md#debmanual
KEYRING=/usr/share/keyrings/nodesource.gpg
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor > "$KEYRING"
gpg --no-default-keyring --keyring "$KEYRING" --list-keys
chmod a+r /usr/share/keyrings/nodesource.gpg

NODE_MAJOR=20
echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list

apt-get update
apt-get install -y nodejs
