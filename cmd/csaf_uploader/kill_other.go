// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022, 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

//go:build !unix

package main

import (
	"log"
	"os/exec"
)

// prepareKillingProcessGroup is currently not implemented on other platforms than unix-likes.
func prepareKillingProcessGroup(*exec.Cmd) {
	log.Println("Warning: creating a process group is not implemented on this platform.")
}
