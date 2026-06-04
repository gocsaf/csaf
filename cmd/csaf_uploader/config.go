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
	"errors"
	"fmt"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/gocsaf/csaf/v3/internal/certs"
	"github.com/gocsaf/csaf/v3/internal/options"
)

const (
	defaultURL       = "https://localhost/cgi-bin/csaf_provider.go"
	defaultAction    = "upload"
	defaultTLP       = "csaf"
	defaultGPGBinary = "gpg"
)

// The supported flag config of the uploader command line
type config struct {
	//lint:ignore SA5008 We are using choice twice: upload, create.
	Action string `short:"a" long:"action" choice:"upload" choice:"create" description:"Action to perform" toml:"action"`
	URL    string `short:"u" long:"url" description:"URL of the CSAF provider" value-name:"URL" toml:"url"`
	//lint:ignore SA5008 We are using choice many times: csaf, white, green, amber, red.
	TLP            string `short:"t" long:"tlp" choice:"csaf" choice:"white" choice:"green" choice:"amber" choice:"red" description:"TLP of the feed" toml:"tlp"`
	ExternalSigned bool   `short:"x" long:"external_signed" description:"CSAF files are signed externally. Assumes .asc files beside CSAF files." toml:"external_signed"`
	NoSchemaCheck  bool   `short:"s" long:"no_schema_check" description:"Do not check files against CSAF JSON schema locally." toml:"no_schema_check"`

	GPG       bool    `long:"gpg" description:"Sign CSAF files via the system gpg binary (delegates passphrase/PIN to gpg-agent)" toml:"gpg"`
	GPGUser   *string `long:"gpg-user" description:"Signing key identity for gpg --local-user (fingerprint/email/keyid)" value-name:"IDENTITY" toml:"gpg_user"`
	GPGBinary string  `long:"gpg-binary" description:"Path to the gpg executable" value-name:"GPG-BIN" toml:"gpg_binary"`

	Key              *string `short:"k" long:"key" description:"OpenPGP key to sign the CSAF files" value-name:"KEY-FILE" toml:"key"`
	Password         *string `short:"p" long:"password" description:"Authentication password for accessing the CSAF provider" value-name:"PASSWORD" toml:"password"`
	Passphrase       *string `short:"P" long:"passphrase" description:"Passphrase to unlock the OpenPGP key" value-name:"PASSPHRASE" toml:"passphrase"`
	ClientCert       *string `long:"client_cert" description:"TLS client certificate file (PEM encoded data)" value-name:"CERT-FILE.crt" toml:"client_cert"`
	ClientKey        *string `long:"client_key" description:"TLS client private key file (PEM encoded data)" value-name:"KEY-FILE.pem" toml:"client_key"`
	ClientPassphrase *string `long:"client_passphrase" description:"Optional passphrase for the client cert (limited, experimental, see downloader doc)" value-name:"PASSPHRASE" toml:"client_passphrase"`

	PasswordInteractive   bool `short:"i" long:"password_interactive" description:"Enter password interactively" toml:"password_interactive"`
	PassphraseInteractive bool `short:"I" long:"passphrase_interactive" description:"Enter OpenPGP key passphrase interactively" toml:"passphrase_interactive"`

	Insecure bool `long:"insecure" description:"Do not check TLS certificates from provider" toml:"insecure"`

	Config  string `short:"c" long:"config" description:"Path to config TOML file" value-name:"TOML-FILE" toml:"-"`
	Version bool   `long:"version" description:"Display version of the binary" toml:"-"`

	clientCerts []tls.Certificate
	cachedAuth  string
	signer      signer
}

// iniPaths are the potential file locations of the the config file.
var configPaths = []string{
	"~/.config/csaf/uploader.toml",
	"~/.csaf_uploader.toml",
	"csaf_uploader.toml",
}

// parseArgsConfig parses the command line and if need a config file.
func parseArgsConfig() ([]string, *config, error) {
	p := options.Parser[config]{
		DefaultConfigLocations: configPaths,
		ConfigLocation:         func(cfg *config) string { return cfg.Config },
		Usage:                  "[OPTIONS] advisories...",
		HasVersion:             func(cfg *config) bool { return cfg.Version },
		SetDefaults: func(cfg *config) {
			cfg.URL = defaultURL
			cfg.Action = defaultAction
			cfg.TLP = defaultTLP
			cfg.GPGBinary = defaultGPGBinary
		},
		// Re-establish default values if not set.
		EnsureDefaults: func(cfg *config) {
			if cfg.URL == "" {
				cfg.URL = defaultURL
			}
			if cfg.Action == "" {
				cfg.Action = defaultAction
			}
			if cfg.TLP == "" {
				cfg.TLP = defaultTLP
			}
			if cfg.GPGBinary == "" {
				cfg.GPGBinary = defaultGPGBinary
			}
		},
	}
	return p.Parse()
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

// readInteractive prints a message to command line and retrieves the password from it.
func readInteractive(prompt string, pw **string) error {
	fmt.Print(prompt)
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	ps := string(p)
	*pw = &ps
	return nil
}

// prepareInteractive prompts for interactive passwords.
func (cfg *config) prepareInteractive() error {
	if cfg.PasswordInteractive {
		if err := readInteractive("Enter auth password: ", &cfg.Password); err != nil {
			return err
		}
	}
	if cfg.PassphraseInteractive {
		if err := readInteractive("Enter OpenPGP passphrase: ", &cfg.Passphrase); err != nil {
			return err
		}
	}
	return nil
}

// loadOpenPGPKey loads an OpenPGP key.
func loadOpenPGPKey(filename string) (*crypto.Key, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return crypto.NewKeyFromArmoredReader(f)
}

// loadKeyRing loads an OpenPGP key from a file and, if a passphrase is given,
// unlocks it, returning a key ring ready for in-process signing. A nil
// passphrase leaves the key as loaded: usable if the key is not protected, and
// failing later at sign time if it is.
func loadKeyRing(filename string, passphrase *string) (*crypto.KeyRing, error) {
	key, err := loadOpenPGPKey(filename)
	if err != nil {
		return nil, err
	}
	if passphrase != nil {
		if key, err = key.Unlock([]byte(*passphrase)); err != nil {
			return nil, err
		}
	}
	return crypto.NewKeyRing(key)
}

// prepareSigning validates the signing related flags and instantiates the
// signer for the selected mode. The three signing modes (system gpg binary,
// file key and external signed) are mutually exclusive. It is the single entry
// point for signing setup: the no-sign and external-signed modes leave
// cfg.signer nil.
func (cfg *config) prepareSigning() error {
	// The three signing modes are mutually exclusive, and neither in-process
	// mode may be combined with externally signed files. These are validated
	// regardless of action, before any signer is constructed.
	if cfg.GPG && cfg.Key != nil {
		return errors.New("--gpg and --key are mutually exclusive")
	}
	if cfg.GPG && cfg.ExternalSigned {
		return errors.New("--gpg and --external_signed are mutually exclusive")
	}
	if cfg.Key != nil && cfg.ExternalSigned {
		return errors.New("--key and --external_signed are mutually exclusive")
	}
	if !cfg.GPG && cfg.GPGUser != nil {
		return errors.New("--gpg-user is only valid in combination with --gpg")
	}

	// A signer is only needed when uploading; other actions leave it nil.
	if cfg.Action != "upload" {
		return nil
	}

	switch {
	case cfg.GPG:
		localUser := ""
		if cfg.GPGUser != nil {
			localUser = *cfg.GPGUser
		}
		cfg.signer = &gpgSigner{binary: cfg.GPGBinary, localUser: localUser}

	case cfg.Key != nil:
		keyRing, err := loadKeyRing(*cfg.Key, cfg.Passphrase)
		if err != nil {
			return err
		}
		cfg.signer = &keyRingSigner{keyRing: keyRing}
	}
	return nil
}

// preparePassword pre-calculates the auth header.
func (cfg *config) preparePassword() error {
	if cfg.Password != nil {
		hash, err := bcrypt.GenerateFromPassword(
			[]byte(*cfg.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		cfg.cachedAuth = string(hash)
	}
	return nil
}

// prepare prepares internal state of a loaded configuration.
func (cfg *config) prepare() error {
	for _, prepare := range []func(*config) error{
		(*config).prepareCertificates,
		(*config).prepareInteractive,
		(*config).prepareSigning,
		(*config).preparePassword,
	} {
		if err := prepare(cfg); err != nil {
			return err
		}
	}
	return nil
}
