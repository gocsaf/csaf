// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

// Package main implements the csaf_aggregator tool.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/gocsaf/csaf/v3/internal/options"

	"github.com/gofrs/flock"
)

func lock(lockFile *string, fn func() error) error {
	if lockFile == nil {
		// No locking configured.
		return fn()
	}

	err := os.MkdirAll(filepath.Dir(*lockFile), 0700)
	if err != nil {
		return fmt.Errorf("file locking failed: %v", err)
	}

	fl := flock.New(*lockFile)
	locked, err := fl.TryLock()
	if err != nil {
		return fmt.Errorf("file locking failed: %v", err)
	}

	if !locked {
		return fmt.Errorf("cannot acquire file lock at %s. Maybe the CSAF aggregator is already running?", *lockFile)
	}
	defer fl.Unlock()
	return fn()
}

func main() {
	_, cfg, err := parseArgsConfig()
	cfg.prepareLogging()
	options.ErrorCheckStructured(err)
	options.ErrorCheckStructured(cfg.prepare())
	p := processor{cfg: cfg, log: slog.Default()}
	options.ErrorCheckStructured(lock(cfg.LockFile, p.process))
}
