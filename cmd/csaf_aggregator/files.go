// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"os"
)

// writeHash writes a hash to file.
func writeHash(fname, name string, hash []byte) error {
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	fmt.Fprintf(f, "%x %s\n", hash, name)
	return f.Close()
}

// writeFileHashes writes a file and its hashes to files.
func writeFileHashes(fname, name string, data, s256, s512 []byte) error {
	// Write the file itself.
	if err := os.WriteFile(fname, data, 0644); err != nil {
		return err
	}
	// Write SHA256 sum.
	if err := writeHash(fname+".sha256", name, s256); err != nil {
		return err
	}
	// Write SHA512 sum.
	return writeHash(fname+".sha512", name, s512)
}
