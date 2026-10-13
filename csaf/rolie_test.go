// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package csaf

import (
	"strings"
	"testing"
)

func TestLoadROLIEFeedNullEntry(t *testing.T) {
	tests := []struct {
		name  string
		feed  string
		count int
	}{
		{
			name:  "only null entry",
			feed:  `{"feed":{"id":"x","title":"t","updated":"2020-01-01T00:00:00Z","entry":[null]}}`,
			count: 0,
		},
		{
			name: "null entry mixed with a real one",
			feed: `{"feed":{"id":"x","title":"t","updated":"2020-01-01T00:00:00Z","entry":[` +
				`null,{"id":"a","title":"a","updated":"2021-01-01T00:00:00Z"}]}}`,
			count: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rf, err := LoadROLIEFeed(strings.NewReader(tt.feed))
			if err != nil {
				t.Fatalf("LoadROLIEFeed failed: %v", err)
			}
			if got := rf.CountEntries(); got != tt.count {
				t.Errorf("CountEntries: got %d, want %d", got, tt.count)
			}
			rf.Entries(func(entry *Entry) {
				if entry == nil {
					t.Fatal("Entries visited a nil entry")
				}
				_ = entry.ID
			})
			rf.SortEntriesByUpdated()
			if e := rf.EntryByID("a"); tt.count > 0 && e == nil {
				t.Error("EntryByID did not find the real entry")
			}
		})
	}
}
