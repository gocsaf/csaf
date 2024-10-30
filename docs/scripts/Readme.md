Scripts for assisting the Integration tests.
They were written on Ubuntu 20.04 TLS amd64 and also tested with 24.04 TLS.

- `prepareUbuntuInstanceForITests.sh` installs the required packages for the csaf integration tests on a naked Ubuntu LTS amd64.

- `TLSConfigsForITest.sh` generates a root CA and webserver cert by running `createRootCAForITest.sh` and `createWebserverCertForITest.sh`
and configures nginx for serving TLS connections.

- `TLSClientConfigsForITest.sh` generates client certificates by calling `createCCForITest.sh` which uses the root certificate initialized before with `createRootCAForITest.sh`. It configures nginx to enable the authentication with client certificate. (This assumes that the same folder name is used to create the root certificate)

- `setupProviderForITest.sh` builds the csaf_provider, writes the required nginx configurations and create the initial folders. IT calls `uploadToProvider.sh` to upload some csaf example files to the provider.

As creating the folders needs to authenticate with the csaf_provider, the configurations of TLS server and Client certificate authentication should be set. So it is recommended to call the scripts in this order: `TLSConfigsForITest.sh`, `TLSClientConfigsForITest.sh`, `setupProviderForITest.sh`

Calling example (as user with sudo privileges):
``` bash
    curl --fail -O https://raw.githubusercontent.com/gocsaf/csaf/main/docs/scripts/prepareUbuntuInstanceForITests.sh
    sudo bash prepareUbuntuInstanceForITests.sh

    git clone https://github.com/gocsaf/csaf.git # --branch <name>
    pushd csaf/docs/scripts/

    export FOLDERNAME=devca1 ORGANAME="CSAF Tools Development (internal)"
    source ./TLSConfigsForITest.sh
    set +e  # for an interactive shell, reverse set -e done by previous line
    ./TLSClientConfigsForITest.sh
    ./setupProviderForITest.sh
    ./testAggregator.sh
    ./testDownloader.sh
```
