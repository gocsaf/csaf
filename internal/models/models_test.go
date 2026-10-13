// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package models

import (
	"strings"
	"testing"
	"time"
)

// TestNewTimeInterval tests the creation of time intervals via NewTimeInterval()
func TestNewTimeInterval(t *testing.T) {
	var (
		before          = time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
		after           = time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC)
		pseudoTimeRange = TimeRange{before, after}
	)
	if NewTimeInterval(after, before) != pseudoTimeRange {
		t.Errorf("Failure: Couldn't generate timerange.")
	}
}

func TestParseDuration(t *testing.T) {

	now := time.Now()

	for _, x := range []struct {
		in        string
		expected  time.Duration
		reference time.Time
		fail      bool
	}{
		{"1h", time.Hour, now, false},
		{"2y", now.Sub(now.AddDate(-2, 0, 0)), now, false},
		{"13M", now.Sub(now.AddDate(0, -13, 0)), now, false},
		{"31d", now.Sub(now.AddDate(0, 0, -31)), now, false},
		{"1h2d3m", now.Sub(now.AddDate(0, 0, -2)) + time.Hour + 3*time.Minute, now, false},
		{strings.Repeat("1", 70) + "y1d", 0, now, true},
	} {
		got, err := parseDuration(x.in, x.reference)
		if err != nil {
			if !x.fail {
				t.Errorf("%q should not fail: %v", x.in, err)
			}
			continue
		}
		if got != x.expected {
			t.Errorf("%q got %v expected %v", x.in, got, x.expected)
		}
	}
}

// TestGuessDate tests whether a sample of strings are correctly parsed into Dates by guessDate()
func TestGuessDate(t *testing.T) {
	if _, guess := guessDate("2006-01-02T15:04:05"); !guess {
		t.Errorf("Failure: Could not guess valid Date from valid string")
	}
	if _, guess := guessDate("2006"); !guess {
		t.Errorf("Failure: Could not guess valid Date from valid string")
	}
	if _, guess := guessDate("2006-01-02"); !guess {
		t.Errorf("Failure: Could not guess valid Date from valid string")
	}

	if _, guess := guessDate(""); guess {
		t.Errorf("Failure: Guessed Date from invalid string")
	}
}

// TestUnmarshalText tests whether UnmarshalText() correctly unmarshals a sample of byteSlices
func TestUnmarshalText(t *testing.T) {
	testTimeRange := NewTimeInterval(
		time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC))
	byteSlice := []byte{'3', 'h'}
	var emptySlice []byte
	if testTimeRange.UnmarshalText(byteSlice) != nil {
		t.Error(testTimeRange.UnmarshalText(byteSlice).Error())
	}
	if testTimeRange.UnmarshalText(emptySlice) == nil {
		t.Errorf("Failure: UnmarshalText succeeded on invalid slice of bytes.")
	}
}

// TestMarshalJSON tests whether MarshalJSON() correctly marshals a sample TimeRange
func TestMarshalJSON(t *testing.T) {
	testTimeRange := NewTimeInterval(
		time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC))
	if _, err := testTimeRange.MarshalJSON(); err != nil {
		t.Errorf("Failure: %v", err)
	}
}

// TestUnmarshalFlag tests whether UnmarshalFlag() correctly extracts time from a given timeRange string.
func TestUnmarshalFlag(t *testing.T) {
	testTimeRange := NewTimeInterval(
		time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC))
	if err := testTimeRange.UnmarshalFlag("3h"); err != nil {
		t.Error(err.Error())
	}
	if err := testTimeRange.UnmarshalFlag("2006-01-02T15:04:05"); err != nil {
		t.Error(err.Error())
	}
	if err := testTimeRange.UnmarshalFlag("2006-01-02T15:04:05a"); err == nil {
		t.Errorf("Failure: Extracted time from invalid string")
	}
	if err := testTimeRange.UnmarshalFlag("2006-01-02T15:04:05a, 2007-01-02T15:04:05"); err == nil {
		t.Errorf("Failure: Extracted time from invalid string")
	}
	if err := testTimeRange.UnmarshalFlag("2006-01-02T15:04:05, 2007-01-02T15:04:05a"); err == nil {
		t.Errorf("Failure: Extracted time from invalid string")
	}
	if err := testTimeRange.UnmarshalFlag("2006-01-02T15:04:05, 2007-01-02T15:04:05"); err != nil {
		t.Error(err.Error())
	}
}

// TestContains tests whether Contains() correctly identifies a sample of points in time to be within
// a timerange or not.
func TestContains(t *testing.T) {
	testTimeRange := NewTimeInterval(
		time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC))
	testPointInTime := time.Date(2010, time.March, 10, 23, 0, 0, 0, time.UTC)
	testPointAfterTime := time.Date(2022, time.March, 10, 23, 0, 0, 0, time.UTC)
	testPointBeforeTime := time.Date(2002, time.March, 10, 23, 0, 0, 0, time.UTC)
	if !testTimeRange.Contains(testPointInTime) {
		t.Errorf("Failure: Did not recognize point within timerange correctly.")
	}
	if testTimeRange.Contains(testPointAfterTime) {
		t.Errorf("Failure: Did not recognize that a point in time was after a timerange correctly.")
	}
	if testTimeRange.Contains(testPointBeforeTime) {
		t.Errorf("Failure: Did not recognize that a point in time was before a timerange correctly.")
	}
}

// TestTimeRangeIntersects checks if TimeRange.Intersects works.
func TestTimeRangeIntersects(t *testing.T) {
	var (
		a = time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
		b = a.AddDate(0, 0, 10)
		c = b.AddDate(0, 0, 10)
		d = c.AddDate(0, 0, 10)
	)
	for _, x := range []struct {
		ranges   [2]TimeRange
		expected bool
	}{
		{ranges: [2]TimeRange{{a, b}, {a, b}}, expected: true},  // equal
		{ranges: [2]TimeRange{{a, b}, {c, d}}, expected: false}, // disjoint
		{ranges: [2]TimeRange{{a, b}, {b, c}}, expected: true},  // touching
		{ranges: [2]TimeRange{{a, c}, {b, d}}, expected: true},  // overlapping
		{ranges: [2]TimeRange{{a, d}, {b, c}}, expected: true},  // containing
		{ranges: [2]TimeRange{{a, b}, {a, c}}, expected: true},  // containing touch left
		{ranges: [2]TimeRange{{b, c}, {a, c}}, expected: true},  // containing touch right
	} {
		got1 := x.ranges[0].Intersects(x.ranges[1])
		got2 := x.ranges[1].Intersects(x.ranges[0])
		if got1 != got2 {
			t.Fatalf("intersecting %v is not commutative", x.ranges)
		}
		if got1 != x.expected {
			t.Fatalf("%v: got %t expected %t", x.ranges, got1, x.expected)
		}
	}
}
