// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/csaf-poc/csaf_distribution/v3/internal/certs"
	"github.com/csaf-poc/csaf_distribution/v3/internal/filter"
	"github.com/csaf-poc/csaf_distribution/v3/internal/models"
	"github.com/csaf-poc/csaf_distribution/v3/internal/options"
)

const (
	defaultWorker         = 2
	defaultPreset         = "mandatory"
	defaultForwardQueue   = 5
	defaultValidationMode = validationStrict
	defaultLogFile        = "downloader.log"
	defaultLogLevel       = slog.LevelInfo
)

type validationMode string

const (
	validationStrict = validationMode("strict")
	validationUnsafe = validationMode("unsafe")
)

type hashAlgorithm string

const (
	algSha256 = hashAlgorithm("sha256")
	algSha512 = hashAlgorithm("sha512")
)

type config struct {
	Directory            string            `short:"d" long:"directory" description:"DIRectory to store the downloaded files in" value-name:"DIR" toml:"directory"`
	Insecure             bool              `long:"insecure" description:"Do not check TLS certificates from provider" toml:"insecure"`
	IgnoreSignatureCheck bool              `long:"ignore_sigcheck" description:"Ignore signature check results, just warn on mismatch" toml:"ignore_sigcheck"`
	ClientCert           *string           `long:"client_cert" description:"TLS client certificate file (PEM encoded data)" value-name:"CERT-FILE" toml:"client_cert"`
	ClientKey            *string           `long:"client_key" description:"TLS client private key file (PEM encoded data)" value-name:"KEY-FILE" toml:"client_key"`
	ClientPassphrase     *string           `long:"client_passphrase" description:"Optional passphrase for the client cert (limited, experimental, see doc)" value-name:"PASSPHRASE" toml:"client_passphrase"`
	Version              bool              `long:"version" description:"Display version of the binary" toml:"-"`
	NoStore              bool              `long:"no_store" short:"n" description:"Do not store files" toml:"no_store"`
	Rate                 *float64          `long:"rate" short:"r" description:"The average upper limit of https operations per second (defaults to unlimited)" toml:"rate"`
	Worker               int               `long:"worker" short:"w" description:"NUMber of concurrent downloads" value-name:"NUM" toml:"worker"`
	Range                *models.TimeRange `long:"time_range" short:"t" description:"RANGE of time from which advisories to download" value-name:"RANGE" toml:"time_range"`
	Folder               string            `long:"folder" short:"f" description:"Download into a given subFOLDER" value-name:"FOLDER" toml:"folder"`
	IgnorePattern        []string          `long:"ignore_pattern" short:"i" description:"Do not download files if their URLs match any of the given PATTERNs" value-name:"PATTERN" toml:"ignore_pattern"`
	ExtraHeader          http.Header       `long:"header" short:"H" description:"One or more extra HTTP header fields" toml:"header"`

	EnumeratePMDOnly bool `long:"enumerate_pmd_only" description:"If this flag is set to true, the downloader will only enumerate valid provider metadata files, but not download documents" toml:"enumerate_pmd_only"`

	RemoteValidator        string   `long:"validator" description:"URL to validate documents remotely" value-name:"URL" toml:"validator"`
	RemoteValidatorCache   string   `long:"validator_cache" description:"FILE to cache remote validations" value-name:"FILE" toml:"validator_cache"`
	RemoteValidatorPresets []string `long:"validator_preset" description:"One or more PRESETS to validate remotely" value-name:"PRESETS" toml:"validator_preset"`

	//lint:ignore SA5008 We are using choice twice: strict, unsafe.
	ValidationMode validationMode `long:"validation_mode" short:"m" choice:"strict" choice:"unsafe" value-name:"MODE" description:"MODE how strict the validation is" toml:"validation_mode"`

	ForwardURL      string      `long:"forward_url" description:"URL of HTTP endpoint to forward downloads to" value-name:"URL" toml:"forward_url"`
	ForwardHeader   http.Header `long:"forward_header" description:"One or more extra HTTP header fields used by forwarding" toml:"forward_header"`
	ForwardQueue    int         `long:"forward_queue" description:"Maximal queue LENGTH before forwarder" value-name:"LENGTH" toml:"forward_queue"`
	ForwardInsecure bool        `long:"forward_insecure" description:"Do not check TLS certificates from forward endpoint" toml:"forward_insecure"`

	LogFile *string `long:"log_file" description:"FILE to log downloading to" value-name:"FILE" toml:"log_file"`
	//lint:ignore SA5008 We are using choice or than once: debug, info, warn, error
	LogLevel *options.LogLevel `long:"log_level" description:"LEVEL of logging details" value-name:"LEVEL" choice:"debug" choice:"info" choice:"warn" choice:"error" toml:"log_level"`

	Config string `short:"c" long:"config" description:"Path to config TOML file" value-name:"TOML-FILE" toml:"-"`

	clientCerts   []tls.Certificate
	ignorePattern filter.PatternMatcher

	//lint:ignore SA5008 We are using choice or than once: sha256, sha512
	PreferredHash hashAlgorithm `long:"preferred_hash" choice:"sha256" choice:"sha512" value-name:"HASH" description:"HASH to prefer" toml:"preferred_hash"`
}

// configPaths are the potential file locations of the config file.
var configPaths = []string{
	"~/.config/csaf/downloader.toml",
	"~/.csaf_downloader.toml",
	"csaf_downloader.toml",
}

// parseArgsConfig parses the command line and if need a config file.
func parseArgsConfig() ([]string, *config, error) {
	var (
		logFile  = defaultLogFile
		logLevel = &options.LogLevel{Level: defaultLogLevel}
	)
	p := options.Parser[config]{
		DefaultConfigLocations: configPaths,
		ConfigLocation:         func(cfg *config) string { return cfg.Config },
		Usage:                  "[OPTIONS] domain...",
		HasVersion:             func(cfg *config) bool { return cfg.Version },
		SetDefaults: func(cfg *config) {
			cfg.Worker = defaultWorker
			cfg.RemoteValidatorPresets = []string{defaultPreset}
			cfg.ValidationMode = defaultValidationMode
			cfg.ForwardQueue = defaultForwardQueue
			cfg.LogFile = &logFile
			cfg.LogLevel = logLevel
		},
		// Re-establish default values if not set.
		EnsureDefaults: func(cfg *config) {
			if cfg.Worker == 0 {
				cfg.Worker = defaultWorker
			}
			if cfg.RemoteValidatorPresets == nil {
				cfg.RemoteValidatorPresets = []string{defaultPreset}
			}
			switch cfg.ValidationMode {
			case validationStrict, validationUnsafe:
			default:
				cfg.ValidationMode = validationStrict
			}
			if cfg.LogFile == nil {
				cfg.LogFile = &logFile
			}
			if cfg.LogLevel == nil {
				cfg.LogLevel = logLevel
			}
		},
	}
	return p.Parse()
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (vm *validationMode) UnmarshalText(text []byte) error {
	switch m := validationMode(text); m {
	case validationStrict, validationUnsafe:
		*vm = m
	default:
		return fmt.Errorf(`invalid value %q (expected "strict" or "unsafe)"`, m)
	}
	return nil
}

// UnmarshalFlag implements [flags.UnmarshalFlag].
func (vm *validationMode) UnmarshalFlag(value string) error {
	var v validationMode
	if err := v.UnmarshalText([]byte(value)); err != nil {
		return err
	}
	*vm = v
	return nil
}

// ignoreFile returns true if the given URL should not be downloaded.
func (cfg *config) ignoreURL(u string) bool {
	return cfg.ignorePattern.Matches(u)
}

// verbose is considered a log level equal or less debug.
func (cfg *config) verbose() bool {
	return cfg.LogLevel.Level <= slog.LevelDebug
}

// prepareDirectory ensures that the working directory
// exists and is setup properly.
func (cfg *config) prepareDirectory() error {
	// If not given use current working directory.
	if cfg.Directory == "" {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		cfg.Directory = dir
		return nil
	}
	// Use given directory
	if _, err := os.Stat(cfg.Directory); err != nil {
		// If it does not exist create it.
		if os.IsNotExist(err) {
			if err = os.MkdirAll(cfg.Directory, 0755); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

// dropSubSeconds drops all parts below resolution of seconds.
func dropSubSeconds(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		t := a.Value.Time()
		a.Value = slog.TimeValue(t.Truncate(time.Second))
	}
	return a
}

// prepareLogging sets up the structured logging.
func (cfg *config) prepareLogging() error {
	var w io.Writer
	if cfg.LogFile == nil || *cfg.LogFile == "" {
		log.Println("using STDERR for logging")
		w = os.Stderr
	} else {
		var fname string
		// We put the log inside the download folder
		// if it is not absolute.
		if filepath.IsAbs(*cfg.LogFile) {
			fname = *cfg.LogFile
		} else {
			fname = filepath.Join(cfg.Directory, *cfg.LogFile)
		}
		f, err := os.OpenFile(fname, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		log.Printf("using %q for logging\n", fname)
		w = f
	}
	ho := slog.HandlerOptions{
		// AddSource: true,
		Level:       cfg.LogLevel.Level,
		ReplaceAttr: dropSubSeconds,
	}
	handler := slog.NewJSONHandler(w, &ho)
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return nil
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

// prepare prepares internal state of a loaded configuration.
func (cfg *config) prepare() error {
	for _, prepare := range []func(*config) error{
		(*config).prepareDirectory,
		(*config).prepareLogging,
		(*config).prepareCertificates,
		(*config).compileIgnorePatterns,
	} {
		if err := prepare(cfg); err != nil {
			return err
		}
	}
	return nil
}
