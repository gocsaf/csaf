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

# using an extended regular expression to whitelist only CSAF 2.0 filenames
# with a sane path

CSAFPATHregexp='^ *"path": "(csaf_2.0/examples/csaf/[a-z0-9+-_]+.json)",'

curl --silent --show-error -H 'Accept: application/vnd.github.v3.raw' \
 https://api.github.com/repos/oasis-tcs/csaf/contents/csaf_2.0/examples/csaf \
 | grep -E "$CSAFPATHregexp" \
 |  sed -E -e "s;${CSAFPATHregexp};\1;" \
 > csaf_examples_pathnames.txt

mkdir csaf_examples
cd csaf_examples

cat ../csaf_examples_pathnames.txt | \
 xargs -I {} \
  curl --silent --show-error -H 'Accept: application/vnd.github.v3.raw' \
   https://api.github.com/repos/oasis-tcs/csaf/contents/{} -O
