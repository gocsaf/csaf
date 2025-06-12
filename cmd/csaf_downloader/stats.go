// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import "log/slog"

// stats contains counters of the downloads.
type stats struct {
	downloadFailed  int
	filenameFailed  int
	schemaFailed    int
	remoteFailed    int
	sha256Failed    int
	sha512Failed    int
	signatureFailed int
	succeeded       int
}

// add adds other stats to this.
func (st *stats) add(o *stats) {
	st.downloadFailed += o.downloadFailed
	st.filenameFailed += o.filenameFailed
	st.schemaFailed += o.schemaFailed
	st.remoteFailed += o.remoteFailed
	st.sha256Failed += o.sha256Failed
	st.sha512Failed += o.sha512Failed
	st.signatureFailed += o.signatureFailed
	st.succeeded += o.succeeded
}

func (st *stats) totalFailed() int {
	return st.downloadFailed +
		st.filenameFailed +
		st.schemaFailed +
		st.remoteFailed +
		st.sha256Failed +
		st.sha512Failed +
		st.signatureFailed
}

// log logs the collected stats.
func (st *stats) log() {
	slog.Info("Download statistics",
		"succeeded", st.succeeded,
		"total_failed", st.totalFailed(),
		"filename_failed", st.filenameFailed,
		"download_failed", st.downloadFailed,
		"schema_failed", st.schemaFailed,
		"remote_failed", st.remoteFailed,
		"sha256_failed", st.sha256Failed,
		"sha512_failed", st.sha512Failed,
		"signature_failed", st.signatureFailed)
}
