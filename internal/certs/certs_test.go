// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package certs

import "testing"

// TestLoadCertificates tests if LoadCertificate correctly loads
// valid certificates and throws an error at invalid certificates,
// keys or passphrases
func TestLoadCertificates(t *testing.T) {
	var (
		testCert       = "data/testclient.crt"
		testKey        = "data/testclientkey.pem"
		passphrase     = "qwer"
		missingCert    = "data/testclientcert_missing.crt"
		missingTestkey = "data/testclientkey_missing.pem"
		privateKey     = "data/privated.pem"
		privateCert    = "data/cert.crt"
	)

	// Try to load cert that is not protected, expect success.
	if cert, err := LoadCertificate(&testCert, &testKey, nil); cert == nil || err != nil {
		t.Errorf("Failure: Couldn't load supposedly valid certificate.")
	}
	// Try to load no cert, expect error.
	if cert, err := LoadCertificate(nil, &testKey, nil); cert != nil || err == nil {
		t.Errorf("Failure: No error despite missing certificate")
	}
	// Try to load cert using a nonexistent key, expect error.
	if cert, err := LoadCertificate(&testCert, &missingTestkey, nil); cert != nil || err == nil {
		t.Errorf("Failure: No Failure while loading certificate using missing key.")
	}
	// Try to decrypt not encrypted cert, expect error
	if cert, err := LoadCertificate(&testCert, &testKey, &passphrase); cert != nil || err == nil {
		t.Errorf("Failure: Could load unprotected valid certificate with passphrase.")
	}
	// Try to load encrypted cert using a nonexistent key, but valid passphrase. Expect error.
	if cert, err := LoadCertificate(&testCert, &missingTestkey, &passphrase); cert != nil || err == nil {
		t.Errorf("Failure: No Failure while loading certificate using missing key with passphrase.")
	}
	// Try to load encrypted cert, expecting success.
	if cert, err := LoadCertificate(&privateCert, &privateKey, &passphrase); cert == nil || err != nil {
		t.Errorf("Failure: Couldn't load supposedly valid encrypted certificate.")
	}
	// Try to load wrong encrypted cert, expecting error.
	if cert, err := LoadCertificate(&testKey, &privateKey, &passphrase); cert != nil || err == nil {
		t.Errorf("Failure: No Failure while loading certificate using wrong encrypted key.")
	}
	// Try to load nonexistent encrypted cert, expecting error.
	if cert, err := LoadCertificate(&missingCert, &privateKey, &passphrase); cert != nil || err == nil {
		t.Errorf("Failure: No Failure while loading nonexistens certificate.")
	}
	// Try to load nonexistent encrypted cert, expecting error.
	if cert, err := LoadCertificate(nil, nil, nil); cert != nil || err != nil {
		t.Errorf("Failure: Expected nil return.")
	}
}
