// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package util

import (
	"bytes"
	"testing"
)

func TestCSV(t *testing.T) {
	buf := new(bytes.Buffer)
	csvWriter := NewFullyQuotedCSWWriter(buf)
	for _, x := range [][]string{{"a", "b", "c"}, {"d", "e", "f"}} {
		if err := csvWriter.Write(x); err != nil {
			t.Error(err)
		}
	}

	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		t.Error(err)
	}
	for _, want := range []string{`"a","b","c"`, `"d","e","f"`} {
		got, err := buf.ReadString('\n')
		if err != nil {
			t.Error(err)
		}
		if got[:len(got)-1] != want {
			t.Errorf("FullyQuotedCSWWriter: Expected %q but got %q.", want, got)
		}
	}
}
