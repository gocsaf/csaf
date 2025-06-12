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
	"log/slog"
	"testing"
)

func TestStatsAdd(t *testing.T) {
	a := stats{
		downloadFailed:  2,
		filenameFailed:  3,
		schemaFailed:    5,
		remoteFailed:    7,
		sha256Failed:    11,
		sha512Failed:    13,
		signatureFailed: 17,
		succeeded:       19,
	}
	b := a
	a.add(&b)
	b.downloadFailed *= 2
	b.filenameFailed *= 2
	b.schemaFailed *= 2
	b.remoteFailed *= 2
	b.sha256Failed *= 2
	b.sha512Failed *= 2
	b.signatureFailed *= 2
	b.succeeded *= 2
	if a != b {
		t.Fatalf("%v != %v", a, b)
	}
}

func TestStatsTotalFailed(t *testing.T) {
	a := stats{
		downloadFailed:  2,
		filenameFailed:  3,
		schemaFailed:    5,
		remoteFailed:    7,
		sha256Failed:    11,
		sha512Failed:    13,
		signatureFailed: 17,
	}
	sum := a.downloadFailed +
		a.filenameFailed +
		a.schemaFailed +
		a.remoteFailed +
		a.sha256Failed +
		a.sha512Failed +
		a.signatureFailed
	if got := a.totalFailed(); got != sum {
		t.Fatalf("got %d expected %d", got, sum)
	}
}

func TestStatsLog(t *testing.T) {
	var out bytes.Buffer
	h := slog.NewJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo})
	orig := slog.Default()
	defer slog.SetDefault(orig)
	slog.SetDefault(slog.New(h))
	a := stats{
		downloadFailed:  2,
		filenameFailed:  3,
		schemaFailed:    5,
		remoteFailed:    7,
		sha256Failed:    11,
		sha512Failed:    13,
		signatureFailed: 17,
		succeeded:       19,
	}
	a.log()
	type result struct {
		Succeeded       int `json:"succeeded"`
		TotalFailed     int `json:"total_failed"`
		FilenameFailed  int `json:"filename_failed"`
		DownloadFailed  int `json:"download_failed"`
		SchemaFailed    int `json:"schema_failed"`
		RemoteFailed    int `json:"remote_failed"`
		SHA256Failed    int `json:"sha256_failed"`
		SHA512Failed    int `json:"sha512_failed"`
		SignatureFailed int `json:"signature_failed"`
	}
	var got result
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := result{
		Succeeded:       a.succeeded,
		TotalFailed:     a.totalFailed(),
		FilenameFailed:  a.filenameFailed,
		DownloadFailed:  a.downloadFailed,
		SchemaFailed:    a.schemaFailed,
		RemoteFailed:    a.remoteFailed,
		SHA256Failed:    a.sha256Failed,
		SHA512Failed:    a.sha512Failed,
		SignatureFailed: a.signatureFailed,
	}
	if got != want {
		t.Fatalf("%v != %v", got, want)
	}
}
