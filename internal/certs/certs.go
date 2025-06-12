// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

// Package certs implement helpers for the tools to handle client side certifacates.
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// LoadCertificate loads an client certificate from file with an optional passphrase.
// Returns nil if no certificate was loaded.
func LoadCertificate(certFile, keyFile, passphrase *string) ([]tls.Certificate, error) {

	switch hasCert, hasKey := certFile != nil, keyFile != nil; {

	case hasCert && !hasKey || !hasCert && hasKey:
		return nil, errors.New(
			"both client-key and client-cert options must be set for the authentication")

	case hasCert:
		// No passphrase
		if passphrase == nil {
			cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
			if err != nil {
				return nil, err
			}
			return []tls.Certificate{cert}, nil
		}

		// With passphrase
		keyFile, err := os.ReadFile(*keyFile)
		if err != nil {
			return nil, err
		}
		keyBlock, _ := pem.Decode(keyFile)

		//lint:ignore SA1019 This is insecure by design.
		keyDER, err := x509.DecryptPEMBlock(keyBlock, []byte(*passphrase))
		if err != nil {
			return nil, err
		}
		// Update keyBlock with the plaintext bytes and clear the now obsolete
		// headers.
		keyBlock.Bytes = keyDER
		keyBlock.Headers = nil

		// Turn the key back into PEM format so we can leverage tls.X509KeyPair,
		// which will deal with the intricacies of error handling, different key
		// types, certificate chains, etc
		keyPEM := pem.EncodeToMemory(keyBlock)

		certPEMBlock, err := os.ReadFile(*certFile)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(certPEMBlock, keyPEM)
		if err != nil {
			return nil, err
		}
		return []tls.Certificate{cert}, nil
	}

	return nil, nil
}
