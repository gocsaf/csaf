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

cat ../../csaf_examples_pathnames_${VERSION}.txt | \
 xargs -I {} \
  curl --silent --show-error -H 'Accept: application/vnd.github.v3.raw' \
   https://api.github.com/repos/oasis-tcs/csaf/contents/{} -O
