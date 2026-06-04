// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

// Package models contains helper models used in the tools internally.
package models

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TimeRange is a time interval.
type TimeRange [2]time.Time

// NewTimeInterval creates a new time range.
// The time values will be sorted.
func NewTimeInterval(a, b time.Time) TimeRange {
	if b.Before(a) {
		a, b = b, a
	}
	return TimeRange{a, b}
}

// guessDate tries to guess an RFC 3339 date time from a given string.
func guessDate(s string) (time.Time, bool) {
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02T15",
		"2006-01-02",
		"2006-01",
		"2006",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// UnmarshalText implements [encoding/text.TextUnmarshaler].
func (tr *TimeRange) UnmarshalText(text []byte) error {
	return tr.UnmarshalFlag(string(text))
}

var (
	yearsMonthsDays     *regexp.Regexp
	yearsMonthsDaysOnce sync.Once
)

// parseDuration extends time.ParseDuration with recognition of
// years, month and days with the suffixes "y", "M" and "d".
// Onlys integer values are detected. The handling of fractional
// values would increase the complexity and may be done in the future.
// The calculate dates are assumed to be before the reference time.
func parseDuration(s string, reference time.Time) (time.Duration, error) {
	var (
		extra time.Duration
		err   error
		used  bool
	)
	parse := func(s string) int {
		if err == nil {
			var v int
			v, err = strconv.Atoi(s)
			return v
		}
		return 0
	}
	// Only compile expression if really needed.
	yearsMonthsDaysOnce.Do(func() {
		yearsMonthsDays = regexp.MustCompile(`[-+]?[0-9]+[yMd]`)
	})
	s = yearsMonthsDays.ReplaceAllStringFunc(s, func(part string) string {
		used = true
		var years, months, days int
		switch suf, num := part[len(part)-1], part[:len(part)-1]; suf {
		case 'y':
			years = -parse(num)
		case 'M':
			months = -parse(num)
		case 'd':
			days = -parse(num)
		}
		date := reference.AddDate(years, months, days)
		extra += reference.Sub(date)
		// Remove from string
		return ""
	})
	if err != nil {
		return 0, err
	}
	// If there is no rest we don't need the stdlib parser.
	if used && s == "" {
		return extra, nil
	}
	// Parse the rest with the stdlib.
	d, err := time.ParseDuration(s)
	if err != nil {
		return d, err
	}
	return d + extra, nil
}

// MarshalJSON implements [encoding/json.Marshaler].
func (tr TimeRange) MarshalJSON() ([]byte, error) {
	s := []string{
		tr[0].Format(time.RFC3339),
		tr[1].Format(time.RFC3339),
	}
	return json.Marshal(s)
}

// UnmarshalFlag implements [go-flags/Unmarshaler].
func (tr *TimeRange) UnmarshalFlag(s string) error {
	s = strings.TrimSpace(s)

	now := time.Now()

	// Handle relative case first.
	if duration, err := parseDuration(s, now); err == nil {
		*tr = NewTimeInterval(now.Add(-duration), now)
		return nil
	}

	a, b, found := strings.Cut(s, ",")
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)

	// Only start date?
	if !found {
		start, ok := guessDate(a)
		if !ok {
			return fmt.Errorf("%q is not a valid RFC date time", a)
		}
		*tr = NewTimeInterval(start, now)
		return nil
	}
	// Real interval
	start, ok := guessDate(a)
	if !ok {
		return fmt.Errorf("%q is not a valid RFC date time", a)
	}
	end, ok := guessDate(b)
	if !ok {
		return fmt.Errorf("%q is not a valid RFC date time", b)
	}
	*tr = NewTimeInterval(start, end)
	return nil
}

// Contains return true if the given time is inside this time interval.
func (tr TimeRange) Contains(t time.Time) bool {
	return !(t.Before(tr[0]) || t.After(tr[1]))
}

// Intersects returns true if the two time ranges intersects.
func (tr TimeRange) Intersects(other TimeRange) bool {
	return !(other[1].Before(tr[0]) || tr[1].Before(other[0]))
}
