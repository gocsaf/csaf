// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package options

import (
	"log/slog"
	"testing"
)

func TestMarshalFlag(t *testing.T) {
	ll := LogLevel{Level: slog.LevelInfo}
	got, err := ll.MarshalFlag()
	if err != nil {
		t.Fatal(err)
	}
	if got != "info" {
		t.Fatalf("got %q expected \"info\"", got)
	}
}

func TestUnmarshalFlag(t *testing.T) {
	for _, x := range []struct {
		input  string
		expect slog.Level
	}{
		{input: "debug", expect: slog.LevelDebug},
		{input: "info", expect: slog.LevelInfo},
		{input: "warn", expect: slog.LevelWarn},
		{input: "error", expect: slog.LevelError},
	} {
		var ll LogLevel
		if err := ll.UnmarshalFlag(x.input); err != nil {
			t.Fatalf("%q error: %v", x.input, err)
		}
		if ll.Level != x.expect {
			t.Fatalf("%q: got %s expected %s", x.input, ll.Level, x.expect)
		}
	}
	var ll LogLevel
	if err := ll.UnmarshalFlag("invalid"); err == nil {
		t.Fatal(`"invalid" should return an error`)
	}
}
