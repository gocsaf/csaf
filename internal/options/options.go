// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

// Package options contains helpers to handle command line options and config files.
package options

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/gocsaf/csaf/v3/util"

	"github.com/BurntSushi/toml"
	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
)

// Parser helps parsing command line arguments and loading
// stored configurations from file.
type Parser[C any] struct {
	// DefaultConfigLocations are the locations where to
	// look for config files if no explicit config was given.
	DefaultConfigLocations []string
	// Usage is the usage prefix for written help.
	Usage string

	// SetDefaults pre-inits a configuration.
	SetDefaults func(*C)
	// EnsureDefaults ensures that default values are set
	// if they are not configured.
	EnsureDefaults func(*C)
	// HasVersion checks if there was a version request.
	HasVersion func(*C) bool
	// ConfigLocation extracts the name of the configuration file.
	ConfigLocation func(*C) string
}

// Parse parses the command line for options.
// If a config file was specified it is loaded.
// Returns the arguments and the configuration.
func (p *Parser[C]) Parse() ([]string, *C, error) {

	var cmdLineOpts C
	if p.SetDefaults != nil {
		p.SetDefaults(&cmdLineOpts)
	}
	// Parse the command line first.
	parser := flags.NewParser(&cmdLineOpts, flags.Default)
	if p.Usage != "" {
		parser.Usage = p.Usage
	}
	args, err := parser.Parse()
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		return nil, nil, err
	}

	// Directly quit if the version flag was set.
	if p.HasVersion != nil && p.HasVersion(&cmdLineOpts) {
		fmt.Println(util.SemVersion)
		os.Exit(0)
	}

	var path string
	// Do we have a config file explicitly given by command line?
	if p.ConfigLocation != nil {
		path = p.ConfigLocation(&cmdLineOpts)
	}
	// Fallback to defaults if we have not found any.
	if path == "" && len(p.DefaultConfigLocations) > 0 {
		path = findConfigFile(p.DefaultConfigLocations)
	}

	// No config file -> We are good.
	if path == "" {
		return args, &cmdLineOpts, nil
	}

	if path, err = homedir.Expand(path); err != nil {
		return nil, nil, err
	}

	// Load the config file
	var fileOpts C
	if err := loadTOML(&fileOpts, path); err != nil {
		return nil, nil, err
	}

	// Parse command line a second time to overwrite the
	// loaded config at places where explicitly command line
	// options where given.
	args, err = flags.NewParser(&fileOpts, flags.Default).Parse()
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		return nil, nil, err
	}

	if p.EnsureDefaults != nil {
		p.EnsureDefaults(&fileOpts)
	}

	return args, &fileOpts, nil
}

// findConfigFile looks for a file in the pre-defined paths in a list of given locations.
// The returned value will be the name of file if found, otherwise an empty string.
func findConfigFile(locations []string) string {
	for _, f := range locations {
		name, err := homedir.Expand(f)
		if err != nil {
			log.Printf("warn: %v\n", err)
			continue
		}
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	return ""
}

// loadTOML loads a configuration from file.
func loadTOML(cfg any, path string) error {
	md, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return err
	}
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		return fmt.Errorf("could not parse %q from %q", undecoded, path)
	}
	return nil
}

// ErrorCheck checks if err is not nil and terminates
// the program if so.
func ErrorCheck(err error) {
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
}

// ErrorCheckStructured checks if err is not nil and terminates the program if
// so. This is similar to [ErrorCheck], but uses [slog] instead of the
// non-structured Go logging.
func ErrorCheckStructured(err error) {
	if err != nil {
		slog.Error("Error while executing program", "err", err)
		os.Exit(1)
	}
}
