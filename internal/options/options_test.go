// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package options

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

type config struct {
	Test           string `long:"Test" description:"Test config struct"`
	Version        bool   `long:"version" description:"test print version"`
	ConfigLocation string `long:"configlocation" description:"test location"`
}

// TestParse helps parsing command line arguments and loading
// stored configurations from file.
func TestParse(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig }()

	os.Args = []string{"cmd"}
	defaultConfigLocation := []string{"data/config.toml"}
	p := Parser[config]{
		DefaultConfigLocations: defaultConfigLocation,
		ConfigLocation: func(cfg *config) string {
			return cfg.ConfigLocation
		},
		Usage:      "[OPTIONS] domain...",
		HasVersion: func(cfg *config) bool { return cfg.Version },
		SetDefaults: func(_ *config) {
		},
		// Re-establish default values if not set.
		EnsureDefaults: func(_ *config) {
		},
	}

	// Test searching for data/config.toml as config file
	if _, _, err := p.Parse(); err != nil {
		t.Errorf("Failure: Valid Parser using config location failed.")
	}

	// Test invalid flag
	os.Args = []string{"cmd", "--invalid"}
	fmt.Println("The following test should produce a warning.")
	if _, _, err := p.Parse(); err == nil {
		t.Errorf("Failure: Parsed invalid flag 'invalid'")
	}

	// Test with no default location; no config is loaded
	var emptyLocation []string
	p.DefaultConfigLocations = emptyLocation
	os.Args = []string{"cmd"}
	if _, _, err := p.Parse(); err != nil {
		t.Errorf("Failure: Valid Parser without config location failed: %s", err.Error())
	}

	// Test failing to load TOML file
	os.Args = []string{"cmd", "--configlocation=data/config_surplus.toml"}
	if _, _, err := p.Parse(); err == nil {
		t.Errorf("Failure: Parsed invalid toml file.")
	}

	// Test failing to expand Path
	os.Args = []string{"cmd", "--configlocation=~~"}
	if _, _, err := p.Parse(); err == nil {
		t.Errorf("Failure: Invalid path expanded.")
	}

	// os.exit tests start here
	// test the help flag
	// if TEST_HELP was set, try parsing the help flag
	if os.Getenv("TEST_HELP") == "1" {
		os.Args = []string{"cmd", "--help"}
		p.Parse()
		return
	}

	// Build subprocess that can be exited
	cmd := exec.Command(orig[0], "-test.run=TestParse")
	cmd.Env = append(os.Environ(), "TEST_HELP=1")
	err := cmd.Run()
	if err != nil {
		t.Fatal(err.Error())
	}

	// test the version flag
	if os.Getenv("TEST_VERSION") == "1" {
		os.Args = []string{"cmd", "--version"}
		p.Parse()
		return
	}

	cmd = exec.Command(orig[0], "-test.run=TestParse")
	cmd.Env = append(os.Environ(), "TEST_VERSION=1")
	err = cmd.Run()
	if err != nil {
		t.Fatal(err.Error())
	}
}

// TestFindConfigFile tests if findConfigFile() correctly finds existing and
// doesn't find nonexisting config files
func TestFindConfigFile(t *testing.T) {
	locations := []string{"data/config.toml"}
	notLocation := []string{"notomllocation"}
	errorExpandLocation := []string{"~~"}

	if findConfigFile(locations) != "data/config.toml" {
		t.Errorf("Failure: Couldn't find existing toml file in specified location")
	}
	if !(findConfigFile(notLocation) == "") {
		t.Errorf("Failure: Supposedly found configuration file in nonexistant location")
	}
	fmt.Println("The following test should produce a warning.")
	if !(findConfigFile(errorExpandLocation) == "") {
		t.Errorf("Failure: Supposedly found configuration file in nonexistant location")
	}
}

// TestLoadToml tests if loadTOML() can correctly load TOML files
func TestLoadToml(t *testing.T) {
	var cfg config
	if err := loadTOML(&cfg, "data/nonexistant.toml"); err.Error() != "open "+
		"data/nonexistant.toml: no such file or directory" {
		t.Errorf("Failure: Didn't throw the correct " +
			"error on trying to load nonexistant file")
	}
	const errMsg = `could not parse ["surplus"] from "data/config_plus.toml"`
	if err := loadTOML(&cfg, "data/config_plus.toml"); err.Error() != errMsg {
		t.Errorf("Failure: Succeeded in parsing nonexistant parameter")
	}
	if err := loadTOML(&cfg, "data/config.toml"); err != nil {
		t.Error(err.Error())
	}
}

// TestErrorCheck checks whether the ErrorChecker correctly logs a fatal error
func TestErrorCheck(t *testing.T) {
	if os.Getenv("TEST_ERROR") == "1" {
		ErrorCheck(errors.New("succesful"))
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestErrorCheck")
	cmd.Env = append(os.Environ(), "TEST_ERROR=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

// TestSecondPassCommandlineParsing checks if the second pass
// of the command line passing is error checked.
func TestSecondPassCommandlineParsing(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig }()

	os.Args = []string{"cmd"}
	p := Parser[config]{
		ConfigLocation: func(_ *config) string {
			// This is a bit stupid.
			os.Args = []string{"cmd", "--invalid"}
			return "data/empty.toml"
		},
	}
	if _, _, err := p.Parse(); err == nil {
		t.Fatalf("Second command line parsing pass did not fail.\n")
	}
}

// TestSecondPassCommandlineHelp triggers the help output in the
// second pass of the command line parsing.
func TestSecondPassCommandlineHelp(t *testing.T) {
	if os.Getenv("TEST_ERROR") == "1" {
		orig := os.Args
		defer func() { os.Args = orig }()

		os.Args = []string{"cmd"}
		p := Parser[config]{
			ConfigLocation: func(_ *config) string {
				// This is a bit stupid.
				os.Args = []string{"cmd", "--help"}
				return "data/empty.toml"
			},
		}
		p.Parse()
		t.Fatalf("Second command line parsing pass help should not reach this.\n")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestSecondPassCommandlineHelp")
	cmd.Env = append(os.Environ(), "TEST_ERROR=1")
	if err := cmd.Run(); err != nil {
		t.Fatalf("process ran with err %v", err)
	}
}
