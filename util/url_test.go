// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package util

import (
	"net/url"
	"testing"
)

func TestBaseUrl(t *testing.T) {
	for _, x := range [][2]string{
		{`http://example.com`, `http://example.com/`},
		{`scheme://example.com`, `scheme://example.com/`},
		{`https://example.com`, `https://example.com/`},
		{`https://example.com:8080/`, `https://example.com:8080/`},
		{`https://user@example.com:8080/`, `https://user@example.com:8080/`},
		{`https://user@example.com:8080/resource`, `https://user@example.com:8080/`},
		{`https://user@example.com:8080/resource/`, `https://user@example.com:8080/resource/`},
		{`https://user@example.com:8080/resource/#fragment`, `https://user@example.com:8080/resource/`},
		{`https://user@example.com:8080/resource/?query=test#fragment`, `https://user@example.com:8080/resource/`},
	} {
		url, _ := url.Parse(x[0])
		if got, err := BaseURL(url); got != x[1] {
			if err != nil {
				t.Error(err)
			}
			t.Errorf("%q: Expected %q but got %q.", x[0], x[1], got)
		}
	}
}
