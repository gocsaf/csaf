// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
)

type entry struct {
	Name       string `json:"name,omitempty"`
	StructName string `json:"struct_name,omitempty"`
	Type       string `json:"type,omitempty"`
}

type document struct {
	Advisory   map[string]entry `json:"advisory"`
	Provider   map[string]entry `json:"provider"`
	Aggregator map[string]entry `json:"aggregator"`
}

type modelRoot struct {
	dir  string
	name string
}

var modelRoots = map[string][3]modelRoot{
	"v20":    {{"csaf/v20", "CSAF"}, {"csaf/v20", "Provider"}, {"csaf/v20", "Aggregator"}},
	"v21":    {{"csaf/v21", "CSAF"}, {"csaf/v21", "Provider"}, {"csaf/v21", "Aggregator"}},
	"legacy": {{"csaf", "Advisory"}, {"csaf", "ProviderMetadata"}, {"csaf", "Aggregator"}},
	"bare":   {{"internal/bare", "CSAF"}, {"internal/bare", "Provider"}, {"internal/bare", "Aggregator"}},
	"shared": {{"csaf/advisory", "CSAF"}, {"csaf/provider", "Provider"}, {"csaf/aggregator", "Aggregator"}},
}

func exportModel(repo, variant string) (*document, error) {
	roots := modelRoots[variant]
	e := &exporter{repo: repo, packages: make(map[string]*sourcePackage)}
	result := &document{}
	var err error
	result.Advisory, err = e.exportRoot(roots[0])
	if err != nil {
		return nil, fmt.Errorf("advisory: %w", err)
	}
	result.Provider, err = e.exportRoot(roots[1])
	if err != nil {
		return nil, fmt.Errorf("provider: %w", err)
	}
	result.Aggregator, err = e.exportRoot(roots[2])
	if err != nil {
		return nil, fmt.Errorf("aggregator: %w", err)
	}
	return result, nil
}

func run() error {
	repo := flag.String("repo", ".", "repository root (relative to the working directory)")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flag.Args())
	}
	for _, variant := range slices.Sorted(maps.Keys(modelRoots)) {
		model, err := exportModel(*repo, variant)
		if err != nil {
			return fmt.Errorf("%s: %w", variant, err)
		}
		data, err := json.MarshalIndent(model, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(variant+"-names.json", append(data, '\n'), 0644); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
