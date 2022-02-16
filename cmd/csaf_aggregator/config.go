// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/BurntSushi/toml"
	"github.com/csaf-poc/csaf_distribution/csaf"
)

const (
	defaultConfigPath = "aggregator.toml"
	defaultWorkers    = 10
)

type provider struct {
	Name   string `toml:"name"`
	Domain string `toml:"domain"`
}

type config struct {
	Workers    int                 `tom:"workers"`
	Aggregator csaf.AggregatorInfo `toml:"aggregator"`
	Providers  []*provider         `toml:"providers"`
}

func (c *config) checkProviders() error {
	already := make(map[string]bool)

	for _, p := range c.Providers {
		if p.Name == "" {
			return errors.New("no name given for provider")
		}
		if p.Domain == "" {
			return errors.New("no domain given for provider")
		}
		if already[p.Name] {
			return fmt.Errorf("provider '%s' is configured more than once", p.Name)
		}
		already[p.Name] = true
	}
	return nil
}

func (c *config) setDefaults() {
	if c.Workers <= 0 {
		n := runtime.NumCPU()
		if len(c.Providers) < n {
			n = len(c.Providers)
		}
		if n > defaultWorkers {
			c.Workers = defaultWorkers
		} else {
			c.Workers = n
		}
	}
}

func (c *config) check() error {
	if len(c.Providers) == 0 {
		return errors.New("no providers given in configuration")
	}

	if err := c.Aggregator.Validate(); err != nil {
		return err
	}

	return c.checkProviders()
}

func loadConfig(path string) (*config, error) {
	if path == "" {
		path = defaultConfigPath
	}

	var cfg config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, err
	}

	cfg.setDefaults()

	if err := cfg.check(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
