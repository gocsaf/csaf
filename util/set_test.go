// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package util

import (
	"reflect"
	"sort"
	"testing"
)

func TestSet(t *testing.T) {
	s := Set[int]{}
	if s.Contains(0) {
		t.Error("Set.Contains: Expected false got true")
	}
	s.Add(0)
	if !s.Contains(0) {
		t.Error("Set.Contains: Expected true got false")
	}

	s0 := Set[int]{}
	s1 := Set[int]{}

	s0.Add(0)
	s0.Add(1)

	s1.Add(0)
	s1.Add(1)
	s1.Add(2)

	diff0 := s0.Difference(s1)
	diff1 := s1.Difference(s0)

	if reflect.DeepEqual(diff0, diff1) {
		t.Errorf("Set.Difference: %q and %q are different", diff0, diff1)
	}

	if s0.ContainsAll(s1) {
		t.Error("Set.ContainsAll: Expected false got true")
	}

	if !s1.ContainsAll(s0) {
		t.Error("Set.ContainsAll: Expected true got false")
	}

	s2 := Set[int]{}
	s2.Add(0)
	s2.Add(1)
	s2.Add(2)
	s2.Add(3)

	wantKeys := []int{0, 1, 2, 3}
	gotKeys := s2.Keys()
	sort.Ints(gotKeys)

	if !reflect.DeepEqual(wantKeys, gotKeys) {
		t.Errorf("Set.Keys: Expected %q got %q", wantKeys, gotKeys)
	}
}
