// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/gocsaf/csaf/v3/internal/certs"
	"github.com/gocsaf/csaf/v3/internal/filter"
	"github.com/gocsaf/csaf/v3/internal/models"
	"github.com/gocsaf/csaf/v3/internal/options"
)

type outputFormat string

const (
	defaultPreset = "mandatory"
	defaultFormat = "json"
)

type config struct {
	Output string `short:"o" long:"output" description:"File name of the generated report" value-name:"REPORT-FILE" toml:"output"`
	//lint:ignore SA5008 We are using choice twice: json, html.
	Format                 outputFormat      `short:"f" long:"format" choice:"json" choice:"html" description:"Format of report" toml:"format"`
	Insecure               bool              `long:"insecure" description:"Do not check TLS certificates from provider" toml:"insecure"`
	ClientCert             *string           `long:"client_cert" description:"TLS client certificate file (PEM encoded data)" value-name:"CERT-FILE" toml:"client_cert"`
	ClientKey              *string           `long:"client_key" description:"TLS client private key file (PEM encoded data)" value-name:"KEY-FILE" toml:"client_key"`
	ClientPassphrase       *string           `long:"client_passphrase" description:"Optional passphrase for the client cert (limited, experimental, see downloader doc)" value-name:"PASSPHRASE" toml:"client_passphrase"`
	Version                bool              `long:"version" description:"Display version of the binary" toml:"-"`
	Verbose                bool              `long:"verbose" short:"v" description:"Verbose output" toml:"verbose"`
	Rate                   *float64          `long:"rate" short:"r" description:"The average upper limit of https operations per second (defaults to unlimited)" toml:"rate"`
	Range                  *models.TimeRange `long:"time_range" short:"t" description:"RANGE of time from which advisories to download" value-name:"RANGE" toml:"time_range"`
	IgnorePattern          []string          `long:"ignore_pattern" short:"i" description:"Do not download files if their URLs match any of the given PATTERNs" value-name:"PATTERN" toml:"ignore_pattern"`
	ExtraHeader            http.Header       `long:"header" short:"H" description:"One or more extra HTTP header fields" toml:"header"`
	RemoteValidator        string            `long:"validator" description:"URL to validate documents remotely" value-name:"URL" toml:"validator"`
	RemoteValidatorCache   string            `long:"validator_cache" description:"FILE to cache remote validations" value-name:"FILE" toml:"validator_cache"`
	RemoteValidatorPresets []string          `long:"validator_preset" description:"One or more presets to validate remotely" toml:"validator_preset"`

	Config string `short:"c" long:"config" description:"Path to config TOML file" value-name:"TOML-FILE" toml:"-"`

	clientCerts   []tls.Certificate
	ignorePattern filter.PatternMatcher
}

// configPaths are the potential file locations of the config file.
var configPaths = []string{
	"~/.config/csaf/checker.toml",
	"~/.csaf_checker.toml",
	"csaf_checker.toml",
}

// UnmarshalText implements [encoding/text.TextUnmarshaler].
func (of *outputFormat) UnmarshalText(text []byte) error {
	s := string(text)
	switch s {
	case "html", "json":
		*of = outputFormat(s)
	default:
		return fmt.Errorf(`%q is neither "html" nor "json"`, s)
	}
	return nil
}

// parseArgsConfig parse the command arguments and loads configuration
// from a configuration file.
func parseArgsConfig() ([]string, *config, error) {
	p := options.Parser[config]{
		DefaultConfigLocations: configPaths,
		ConfigLocation: func(cfg *config) string {
			return cfg.Config
		},
		Usage:      "[OPTIONS] domain...",
		HasVersion: func(cfg *config) bool { return cfg.Version },
		SetDefaults: func(cfg *config) {
			cfg.Format = defaultFormat
			cfg.RemoteValidatorPresets = []string{defaultPreset}
		},
		// Re-establish default values if not set.
		EnsureDefaults: func(cfg *config) {
			if cfg.Format == "" {
				cfg.Format = defaultFormat
			}
			if cfg.RemoteValidatorPresets == nil {
				cfg.RemoteValidatorPresets = []string{defaultPreset}
			}
		},
	}
	return p.Parse()
}

// protectedAccess returns true if we have client certificates or
// extra http headers configured.
// This may be a wrong assumption, because the certs are not checked
// for their domain and custom headers may have other purposes.
func (cfg *config) protectedAccess() bool {
	return len(cfg.clientCerts) > 0 || len(cfg.ExtraHeader) > 0
}

// ignoreFile returns true if the given URL should not be downloaded.
func (cfg *config) ignoreURL(u string) bool {
	return cfg.ignorePattern.Matches(u)
}

// prepare prepares internal state of a loaded configuration.
func (cfg *config) prepare() error {

	// Pre-compile the regexes used to check if we need to ignore advisories.
	if err := cfg.compileIgnorePatterns(); err != nil {
		return err
	}

	// Load client certs.
	return cfg.prepareCertificates()
}

// compileIgnorePatterns compiles the configure patterns to be ignored.
func (cfg *config) compileIgnorePatterns() error {
	pm, err := filter.NewPatternMatcher(cfg.IgnorePattern)
	if err != nil {
		return err
	}
	cfg.ignorePattern = pm
	return nil
}

// prepareCertificates loads the client side certificates used by the HTTP client.
func (cfg *config) prepareCertificates() error {
	cert, err := certs.LoadCertificate(
		cfg.ClientCert, cfg.ClientKey, cfg.ClientPassphrase)
	if err != nil {
		return err
	}
	cfg.clientCerts = cert
	return nil
}
