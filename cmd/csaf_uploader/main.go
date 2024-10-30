// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

// Implements a command line tool that uploads csaf documents to csaf_provider.
package main

import "github.com/gocsaf/csaf/v3/internal/options"

func main() {
	args, cfg, err := parseArgsConfig()
	options.ErrorCheck(err)
	options.ErrorCheck(cfg.prepare())
	p := &processor{cfg: cfg}
	options.ErrorCheck(p.run(args))
}
