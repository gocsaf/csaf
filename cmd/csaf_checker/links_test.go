// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gocsaf/csaf/v3/util"
)

const page0 = `<html>
<body>
	<a href="not-a-json">Not a JSON</a>
	<a href="link0.json">link0</a>
	<ol>
		<li><a href="link1.json">link1</a></li>
		<li><a href="link2.json">link1</a></li>
	</ol>
	<p>
	<div>
		<li><a href="link3.json">link1</a></li>
	</div>
	<p>
</body>
</html>`

func TestLinksOnPage(t *testing.T) {
	var links []string

	err := linksOnPage(
		strings.NewReader(page0),
		func(s string) error {
			if strings.HasSuffix(s, ".json") {
				links = append(links, s)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if l := len(links); l != 4 {
		t.Fatalf("Expected 4 links, go %d\n", l)
	}

	for i, link := range links {
		href := fmt.Sprintf("link%d.json", i)
		if href != link {
			t.Fatalf("Expected link '%s', got '%s'\n", href, link)
		}
	}
}

func Test_listed(t *testing.T) {
	tests := []struct {
		name    string
		badDirs util.Set[string]
		path    string
		want    bool
	}{
		{
			name:    "listed path",
			badDirs: util.Set[string]{},
			path:    "/white/avendor-advisory-0004.json",
			want:    true,
		},
		{
			name:    "badDirs contains path",
			badDirs: util.Set[string]{"/white/": {}},
			path:    "/white/avendor-advisory-0004.json",
			want:    false,
		},
		{
			name:    "not found",
			badDirs: util.Set[string]{},
			path:    "/not-found/resource.json",
			want:    false,
		},
		{
			name:    "badDirs does not contain path",
			badDirs: util.Set[string]{"/bad-dir/": {}},
			path:    "/white/avendor-advisory-0004.json",
			want:    true,
		},
		{
			name:    "unlisted path",
			badDirs: util.Set[string]{},
			path:    "/white/avendor-advisory-0004-not-listed.json",
			want:    false,
		},
	}

	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			serverURL := ""
			fs := http.FileServer(http.Dir("../../testdata/simple-directory-provider"))
			server := httptest.NewTLSServer(fs)
			defer server.Close()

			serverURL = server.URL

			hClient := server.Client()
			client := util.Client(hClient)

			pgs := pages{}
			cfg := config{RemoteValidator: "", RemoteValidatorCache: ""}
			p, err := newProcessor(&cfg)
			if err != nil {
				t.Error(err)
			}
			p.client = client

			badDirs := util.Set[string]{}
			for dir := range test.badDirs {
				badDirs.Add(serverURL + dir)
			}

			got, _ := pgs.listed(serverURL+test.path, p, badDirs)
			if got != test.want {
				t.Errorf("%q: Expected %t but got %t.", test.name, test.want, got)
			}
		})
	}
}
