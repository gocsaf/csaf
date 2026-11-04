#!/usr/bin/env bash
#
# Desc: Tries getting csaf 2.0 examples from api.github. Do not run too often!
#
# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e

# The OASIS repo has subfolders for CSAF 2.0 and 2.1 examples
VERSION=${1:?usage: $0 2.0|2.1}

# using an extended regular expression to whitelist CSAF 2.0 or 2.1
# filenames with a sane path
CSAFPATHregexp="^ *\"path\": \"(csaf_${VERSION}/examples/csaf/[a-z0-9+-_]+.json)\","

curl --silent --show-error -H 'Accept: application/vnd.github.v3.raw' \
 https://api.github.com/repos/oasis-tcs/csaf/contents/csaf_${VERSION}/examples/csaf \
 | grep -E "$CSAFPATHregexp" \
 |  sed -E -e "s;${CSAFPATHregexp};\1;" \
 > csaf_examples_pathnames_${VERSION}.txt

mkdir -p csaf_examples/${VERSION}
cd csaf_examples/${VERSION}

if [ "$VERSION" = "2.0" ]; then

    cat ../../csaf_examples_pathnames_${VERSION}.txt | \
    xargs -I {} \
      curl --silent --show-error \
      -H 'Accept: application/vnd.github.v3.raw' \
      https://api.github.com/repos/oasis-tcs/csaf/contents/{} -O

elif [ "$VERSION" = "2.1" ]; then

    curl --silent --show-error -O "https://raw.githubusercontent.com/csaf-testsuite/distribution/refs/heads/2.1_main/data/.well-known/csaf/clear/2026/csaf2_1.json"
    curl --silent --show-error -O "https://raw.githubusercontent.com/csaf-testsuite/distribution/refs/heads/2.1_main/data/.well-known/csaf/green/2026/csaf2_1green.json"
    curl --silent --show-error -O "https://raw.githubusercontent.com/csaf-testsuite/distribution/refs/heads/2.1_main/data/.well-known/csaf/amber/2026/csaf2_1amber.json"
    curl --silent --show-error -O "https://raw.githubusercontent.com/csaf-testsuite/distribution/refs/heads/2.1_main/data/.well-known/csaf/amber+strict/2026/csaf2_1amberstrict.json"
    curl --silent --show-error -O "https://raw.githubusercontent.com/csaf-testsuite/distribution/refs/heads/2.1_main/data/.well-known/csaf/red/2026/csaf2_1red.json"

fi
