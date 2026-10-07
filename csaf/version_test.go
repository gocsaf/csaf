// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package csaf

import (
	"encoding/json"
	"testing"
)

func TestDetectVersion(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		kind    DocumentKind
		version SpecVersion
	}{
		{"advisory 2.0", `{"document":{"csaf_version":"2.0"}}`, DocumentAdvisory, Version20},
		{"advisory 2.1", `{"document":{"csaf_version":"2.1"}}`, DocumentAdvisory, Version21},
		{"provider 2.0", `{"metadata_version":"2.0"}`, DocumentProviderMetadata, Version20},
		{"provider 2.1", `{"metadata_version":"2.1"}`, DocumentProviderMetadata, Version21},
		{"aggregator 2.0", `{"aggregator_version":"2.0"}`, DocumentAggregator, Version20},
		{"aggregator 2.1", `{"aggregator_version":"2.1"}`, DocumentAggregator, Version21},
		{"skip nested values", `{"extra":[{"metadata_version":"3.0"}],"document":{"csaf_version":"2.1"}}`, DocumentAdvisory, Version21},
		// Without early return: error because both advisory and provider version fields are present.
		{"first version wins", `{"document":{"csaf_version":"2.1"},"metadata_version":"2.0"}`, DocumentAdvisory, Version21},
		// Without early return: error because the document and root objects are not closed.
		{"nested version stops before object end", `{"document":{"csaf_version":"2.1"`, DocumentAdvisory, Version21},
		{"missing version", `{}`, DocumentUnknown, ""},
		{"null version", `{"metadata_version":null}`, DocumentUnknown, ""},
		{"unsupported version", `{"document":{"csaf_version":"3.0"}}`, DocumentUnknown, ""},
		{"numeric version", `{"metadata_version":2.1}`, DocumentUnknown, ""},
		{"malformed value before version", `{"extra":[1,],"metadata_version":"2.1"}`, DocumentUnknown, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kind, version, err := DetectVersion(json.RawMessage(test.raw))
			// DocumentUnknown marks cases where we expect an error.
			if test.kind == DocumentUnknown {
				if err == nil {
					t.Fatal("expected an error")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if kind != test.kind || version != test.version {
				// https://go.dev/wiki/TestComments#got-before-want
				t.Fatalf("DetectVersion(%q) = (%v, %q), want (%v, %q)", test.raw, kind, version, test.kind, test.version)
			}
		})
	}
}
