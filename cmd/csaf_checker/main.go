// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

// Package main implements the csaf_checker tool.
package main

import (
	"log"

	"github.com/gocsaf/csaf/v3/internal/options"
)

// run uses a processor to check all the given domains or direct urls
// and generates a report.
func run(cfg *config, domains []string) (*Report, error) {
	p, err := newProcessor(cfg)
	if err != nil {
		return nil, err
	}
	defer p.close()
	return p.run(domains)
}

func main() {
	domains, cfg, err := parseArgsConfig()
	options.ErrorCheck(err)
	options.ErrorCheck(cfg.prepare())

	if len(domains) == 0 {
		log.Println("No domain or direct url given.")
		return
	}

	report, err := run(cfg, domains)
	options.ErrorCheck(err)

	options.ErrorCheck(report.write(cfg.Format, cfg.Output))
}
