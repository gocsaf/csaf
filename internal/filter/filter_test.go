// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package filter

import (
	"testing"
)

// TestNewPatternMatcher tests if NewPatternMatcher recognizes
// whether a set of sample regular expressions is valid
func TestNewPatternMatcher(t *testing.T) {
	var regex []string
	if pm, err := NewPatternMatcher(regex); pm == nil || err != nil {
		t.Errorf("Failure: Did not compile valid regex pattern")
	}
	regex = append(regex, "++")
	if pm, err := NewPatternMatcher(regex); pm != nil || err == nil {
		t.Errorf("Failure: No error returned at invalid compile pattern")
	}
}

// TestMatches tests if Matches returns whether a given string
// matches a sample of the expressions correctly.
func TestMatches(t *testing.T) {
	regex := []string{"a"}
	pm, _ := NewPatternMatcher(regex)
	if !pm.Matches("a") {
		t.Errorf("Failure: Did not match two identical strings")
	}
	if pm.Matches("b") {
		t.Errorf("Failure: Matched two non-matching strings")
	}
}
