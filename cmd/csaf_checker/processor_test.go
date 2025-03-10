// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"text/template"

	"github.com/gocsaf/csaf/v3/internal/testutil"
	"github.com/gocsaf/csaf/v3/util"
)

func getRequirementTestData(t *testing.T, params testutil.ProviderParams, directoryProvider bool) []Requirement {
	path := "../../testdata/processor-requirements/"
	if params.EnableSha256 {
		path += "sha256-"
	}
	if params.EnableSha512 {
		path += "sha512-"
	}
	if params.ForbidSha256 {
		path += "forbid-sha256-"
	}
	if params.ForbidSha512 {
		path += "forbid-sha512-"
	}
	if directoryProvider {
		path += "directory"
	} else {
		path += "rolie"
	}
	path += ".json"

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	tmplt, err := template.New("base").Parse(string(content))
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	err = tmplt.Execute(&output, params)
	if err != nil {
		t.Fatal(err)
	}
	var requirement []Requirement
	err = json.Unmarshal(output.Bytes(), &requirement)
	if err != nil {
		t.Fatal(err)
	}
	return requirement
}

func TestContentTypeReport(t *testing.T) {
	serverURL := ""
	params := testutil.ProviderParams{
		URL:             "",
		EnableSha256:    true,
		EnableSha512:    true,
		ForbidSha256:    true,
		ForbidSha512:    true,
		JSONContentType: "application/json; charset=utf-8",
	}
	server := httptest.NewTLSServer(testutil.ProviderHandler(&params, false))
	defer server.Close()

	serverURL = server.URL
	params.URL = server.URL

	hClient := server.Client()
	client := util.Client(hClient)

	cfg := config{}
	err := cfg.prepare()
	if err != nil {
		t.Fatalf("SHA marking config failed: %v", err)
	}
	p, err := newProcessor(&cfg)
	if err != nil {
		t.Fatalf("could not init downloader: %v", err)
	}
	p.client = client

	report, err := p.run([]string{serverURL + "/provider-metadata.json"})
	if err != nil {
		t.Errorf("Content-Type-Report: Expected no error, got: %v", err)
	}

	got := report.Domains[0].Requirements
	idx := slices.IndexFunc(got, func(e *Requirement) bool {
		return e.Num == 7
	})
	if idx == -1 {
		t.Error("Content-Type-Report: Could not find requirement")
	} else {
		message := got[idx].Messages[0]
		if message.Type != ErrorType || !strings.Contains(message.Text, "should be 'application/json'") {
			t.Errorf("Content-Type-Report: Content Type Error, got %v", message)
		}
	}

	p.close()
}

func TestShaMarking(t *testing.T) {
	tests := []struct {
		name              string
		directoryProvider bool
		enableSha256      bool
		enableSha512      bool
		forbidSha256      bool
		forbidSha512      bool
	}{
		{
			name:              "deliver sha256 and sha512",
			directoryProvider: false,
			enableSha256:      true,
			enableSha512:      true,
		},
		{
			name:              "enable sha256 and sha512, forbid fetching",
			directoryProvider: false,
			enableSha256:      true,
			enableSha512:      true,
			forbidSha256:      true,
			forbidSha512:      true,
		},
		{
			name:              "enable sha256 and sha512, forbid sha256",
			directoryProvider: false,
			enableSha256:      true,
			enableSha512:      true,
			forbidSha256:      true,
			forbidSha512:      false,
		},
		{
			name:              "enable sha256 and sha512, forbid sha512",
			directoryProvider: false,
			enableSha256:      true,
			enableSha512:      true,
			forbidSha256:      false,
			forbidSha512:      true,
		},
		{
			name:              "only deliver sha256",
			directoryProvider: false,
			enableSha256:      true,
			enableSha512:      false,
		},
		{
			name:              "only deliver sha512",
			directoryProvider: false,
			enableSha256:      false,
			enableSha512:      true,
		},
		{
			name:              "deliver sha256 and sha512, directory provider",
			directoryProvider: true,
			enableSha256:      true,
			enableSha512:      true,
		},
		{
			name:              "only deliver sha256, directory provider",
			directoryProvider: true,
			enableSha256:      true,
			enableSha512:      false,
		},
		{
			name:              "only deliver sha512, directory provider",
			directoryProvider: true,
			enableSha256:      false,
			enableSha512:      true,
		},
		{
			name:              "no hash",
			directoryProvider: false,
			enableSha256:      false,
			enableSha512:      false,
		},
		{
			name:              "no hash, directory provider",
			directoryProvider: true,
			enableSha256:      false,
			enableSha512:      false,
		},
	}

	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			serverURL := ""
			params := testutil.ProviderParams{
				URL:          "",
				EnableSha256: test.enableSha256,
				EnableSha512: test.enableSha512,
				ForbidSha256: test.forbidSha256,
				ForbidSha512: test.forbidSha512,
			}
			server := httptest.NewTLSServer(testutil.ProviderHandler(&params, test.directoryProvider))
			defer server.Close()

			serverURL = server.URL
			params.URL = server.URL

			hClient := server.Client()
			client := util.Client(hClient)

			cfg := config{}
			err := cfg.prepare()
			if err != nil {
				t.Fatalf("SHA marking config failed: %v", err)
			}
			p, err := newProcessor(&cfg)
			if err != nil {
				t.Fatalf("could not init downloader: %v", err)
			}
			p.client = client

			report, err := p.run([]string{serverURL + "/provider-metadata.json"})
			if err != nil {
				t.Errorf("SHA marking %v: Expected no error, got: %v", test.name, err)
			}
			expected := getRequirementTestData(t,
				testutil.ProviderParams{
					URL:          serverURL,
					EnableSha256: test.enableSha256,
					EnableSha512: test.enableSha512,
					ForbidSha256: test.forbidSha256,
					ForbidSha512: test.forbidSha512,
				},
				test.directoryProvider)
			for i, got := range report.Domains[0].Requirements {
				if !reflect.DeepEqual(expected[i], *got) {
					t.Errorf("SHA marking %v: Expected %v, got %v", test.name, expected[i], *got)
				}
			}

			p.close()
		})
	}
}
