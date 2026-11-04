#!/usr/bin/env bash
#
# Desc: Call ./downloadExamples.sh and then try csaf_uploader.
#
# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e

# assumes that the following script only downloads file with filenames
# following https://docs.oasis-open.org/csaf/csaf/v2.0/cs01/csaf-v2.0-cs01.html#51-filename
# which are save to process further
./downloadExamples.sh 2.0
./downloadExamples.sh 2.1

# uploadSingle uploads a single advisory
uploadSingle() {
../../bin-linux-amd64/csaf_uploader --insecure -P security123 -a upload \
            -t "$1" \
            -u https://localhost:8443/cgi-bin/csaf_provider.go \
            --client_cert ~/devca1/testclient1.crt \
            --client_key ~/devca1/testclient1-key.pem \
            ./csaf_examples/"$3"/"$2"
}


# upload uploads examples per CSAF version with their TLPs
upload() {
    local version=$1
    shift
    local tlps=("$@")
    local counter=0
    for f in $(ls csaf_examples/$version); do
            uploadSingle "${tlps[$((counter++ % ${#tlps[@]}))]}" "$f" "$version"
    done
}

upload 2.0 "white" "green" "amber" "red"

# For 2.1, we have different TLPs, so we make sure to match them

uploadSingle "clear" "csaf2_1.json" "2.1"
uploadSingle "green" "csaf2_1green.json" "2.1"
uploadSingle "amber" "csaf2_1amber.json" "2.1"
uploadSingle "amber+strict" "csaf2_1amberstrict.json"  "2.1"
uploadSingle "red" "csaf2_1red.json" "2.1"
