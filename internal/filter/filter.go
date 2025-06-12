// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

// Package filter implements helps to filter advisories.
package filter

import (
	"fmt"
	"regexp"
)

// PatternMatcher is a list of regular expressions.
type PatternMatcher []*regexp.Regexp

// NewPatternMatcher compiles a new list of regular expression from
// a given list of strings.
func NewPatternMatcher(patterns []string) (PatternMatcher, error) {
	pm := make(PatternMatcher, 0, len(patterns))
	for _, pattern := range patterns {
		expr, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid ignore pattern: %w", err)
		}
		pm = append(pm, expr)
	}
	return pm, nil
}

// Matches returns true if the given string matches any of the expressions.
func (pm PatternMatcher) Matches(s string) bool {
	for _, expr := range pm {
		if expr.MatchString(s) {
			return true
		}
	}
	return false
}
