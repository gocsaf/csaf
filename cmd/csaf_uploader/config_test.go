// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import "testing"

// TestPrepareSigningMutualExclusion covers acceptance criteria 2 and 3: the
// system-gpg mode is mutually exclusive with the file-key and external-signed
// modes, each producing its specific error, while --gpg on its own is accepted.
func TestPrepareSigningMutualExclusion(t *testing.T) {
	key := "some-key-file"
	user := "0xDEADBEEF"

	tests := []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{
			name: "gpg and key are mutually exclusive",
			cfg: config{
				GPG: true,
				Key: &key,
			},
			wantErr: "--gpg and --key are mutually exclusive",
		},
		{
			name: "gpg and external_signed are mutually exclusive",
			cfg: config{
				GPG:            true,
				ExternalSigned: true,
			},
			wantErr: "--gpg and --external_signed are mutually exclusive",
		},
		{
			name: "key and external_signed are mutually exclusive",
			cfg: config{
				Key:            &key,
				ExternalSigned: true,
			},
			wantErr: "--key and --external_signed are mutually exclusive",
		},
		{
			name: "gpg alone is accepted",
			cfg: config{
				GPG: true,
			},
		},
		{
			name: "gpg with gpg-user and gpg-binary is accepted",
			cfg: config{
				GPG:       true,
				GPGUser:   &user,
				GPGBinary: "gpg",
			},
		},
		{
			name: "key alone is accepted (no gpg)",
			cfg: config{
				Key: &key,
			},
		},
		{
			name: "external_signed alone is accepted (no gpg)",
			cfg: config{
				ExternalSigned: true,
			},
		},
		{
			name: "gpg-user without gpg is rejected",
			cfg: config{
				GPGUser: &user,
			},
			wantErr: "--gpg-user is only valid in combination with --gpg",
		},
		{
			name: "no signing flags is accepted",
			cfg:  config{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			err := cfg.prepareSigning()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("prepareSigning() returned unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("prepareSigning() = nil, want error %q", tt.wantErr)
			case tt.wantErr != "" && err.Error() != tt.wantErr:
				t.Fatalf("prepareSigning() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestPrepareSigningGPGModeInstallsSigner confirms that gpg mode installs a
// gpgSigner without touching the file-key loading path.
func TestPrepareSigningGPGModeInstallsSigner(t *testing.T) {
	cfg := config{GPG: true, Action: "upload"}
	if err := cfg.prepareSigning(); err != nil {
		t.Fatalf("prepareSigning() in gpg mode returned error: %v", err)
	}
	if _, ok := cfg.signer.(*gpgSigner); !ok {
		t.Fatalf("prepareSigning() gpg mode signer = %T, want *gpgSigner", cfg.signer)
	}
}
