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
	"context"
	"log"
	"os"
	"os/signal"

	"net/http"

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	return p.run(ctx, domains)
}

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
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
