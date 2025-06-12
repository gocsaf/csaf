// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

// Package main implements the csaf_downloader tool.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"github.com/gocsaf/csaf/v3/internal/options"
)

func run(cfg *config, domains []string) error {
	d, err := newDownloader(cfg)
	if err != nil {
		return err
	}
	defer d.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	if cfg.ForwardURL != "" {
		f := newForwarder(cfg)
		go f.run()
		defer func() {
			f.log()
			f.close()
		}()
		d.forwarder = f
	}

	// If the enumerate-only flag is set, enumerate found PMDs,
	// else use the normal load method
	if cfg.EnumeratePMDOnly {
		return d.runEnumerate(domains)
	}
	return d.run(ctx, domains)
}

func main() {

	domains, cfg, err := parseArgsConfig()
	options.ErrorCheck(err)
	options.ErrorCheck(cfg.prepare())

	if len(domains) == 0 {
		slog.Warn("No domains given.")
		return
	}

	options.ErrorCheck(run(cfg, domains))
}
