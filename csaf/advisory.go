// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package csaf

import (
	"os"

	"github.com/gocsaf/csaf/v3/internal/misc"
)

// LoadAdvisory loads and validates a CSAF 2.1 advisory from a file.
func LoadAdvisory(filename string) (*Advisory, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var advisory Advisory
	if err := misc.StrictJSONParse(file, &advisory); err != nil {
		return nil, err
	}
	if err := advisory.Validate(); err != nil {
		return nil, err
	}
	return &advisory, nil
}
