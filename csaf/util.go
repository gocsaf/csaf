// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package csaf

import (
	"bufio"
	"io"
	"strings"
)

// ExtractProviderURL extracts URLs of provider metadata.
// If all is true all URLs are returned. Otherwise only the first is returned.
func ExtractProviderURL(r io.Reader, all bool) ([]string, error) {
	const csaf = "CSAF:"

	var urls []string

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, csaf) {
			urls = append(urls, strings.TrimSpace(line[len(csaf):]))
			if !all {
				return urls, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}
