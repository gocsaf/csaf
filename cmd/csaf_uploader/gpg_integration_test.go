// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// TestGPGSignerRealGPGWireCompatibility is the optional, gated integration test
// for acceptance criterion 10's verification half: a signature produced by the
// real gpg binary via gpgSigner must verify against the uploaded bytes using
// the same gopenpgp path the csaf_provider server uses
// (NewPGPSignatureFromArmored + VerifyDetached). It is fully hermetic: a
// throwaway key is created in an ephemeral GNUPGHOME under a temp dir and no
// network is used. The test skips cleanly when gpg is unavailable.
func TestGPGSignerRealGPGWireCompatibility(t *testing.T) {
	gpgBin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg binary not available; skipping real-gpg integration test")
	}

	// gpg-agent creates a UNIX socket inside GNUPGHOME; its full path must stay
	// under the ~108-byte sockaddr_un limit. The default deeply-nested
	// t.TempDir() path can exceed that, so create a short home under the system
	// temp dir and register cleanup ourselves.
	gnupgHome, err := os.MkdirTemp("", "csaf-gpg-it-")
	if err != nil {
		t.Fatalf("creating ephemeral GNUPGHOME: %v", err)
	}
	if err := os.Chmod(gnupgHome, 0o700); err != nil {
		t.Fatalf("chmod GNUPGHOME: %v", err)
	}
	if len(gnupgHome) > 80 {
		t.Skipf("GNUPGHOME path too long for gpg-agent sockets (%d bytes): %s", len(gnupgHome), gnupgHome)
	}

	// Extra environment entries pointing gpg at the ephemeral home. They are
	// appended to the inherited environment both by the helper commands (via
	// env) and by the production gpgSigner (via its env field).
	gpgEnv := []string{
		"GNUPGHOME=" + gnupgHome,
		// Keep gpg fully non-interactive and offline.
		"GPG_TTY=",
	}
	env := append(os.Environ(), gpgEnv...)

	// Stop the agent and remove the home after the test (LIFO: kill first).
	t.Cleanup(func() { os.RemoveAll(gnupgHome) })
	t.Cleanup(func() { killAgent(t, gpgBin, gnupgHome, env) })

	// Generate a throwaway, passphrase-less RSA key in the ephemeral home.
	genKey(t, gpgBin, gnupgHome, env)

	// Export the public key so we can verify with gopenpgp.
	pubArmored := exportPublicKey(t, gpgBin, gnupgHome, env)
	pubKey, err := crypto.NewKeyFromArmored(pubArmored)
	if err != nil {
		t.Fatalf("parsing exported public key: %v", err)
	}
	verifyRing, err := crypto.NewKeyRing(pubKey)
	if err != nil {
		t.Fatalf("building verify key ring: %v", err)
	}

	// Sign via gpgSigner with GNUPGHOME pointed at the ephemeral home.
	doc := []byte(`{"document":{"title":"integration"}}`)

	s := &gpgSigner{binary: gpgBin, env: gpgEnv}
	armored, err := s.sign(context.Background(), doc)
	if err != nil {
		t.Fatalf("gpgSigner.sign with real gpg failed: %v", err)
	}
	if !strings.Contains(armored, "BEGIN PGP SIGNATURE") {
		t.Fatalf("real gpg output is not an armored signature:\n%s", armored)
	}

	// Verify the detached signature exactly as the server would.
	pgpSig, err := crypto.NewPGPSignatureFromArmored(armored)
	if err != nil {
		t.Fatalf("NewPGPSignatureFromArmored: %v", err)
	}
	if err := verifyRing.VerifyDetached(
		crypto.NewPlainMessage(doc), pgpSig, crypto.GetUnixTime(),
	); err != nil {
		t.Fatalf("VerifyDetached on real-gpg signature failed: %v", err)
	}
}

func genKey(t *testing.T, gpgBin, home string, env []string) {
	t.Helper()
	batch := strings.Join([]string{
		"%no-protection",
		"Key-Type: RSA",
		"Key-Length: 2048",
		"Subkey-Type: RSA",
		"Subkey-Length: 2048",
		"Name-Real: CSAF Integration Tester",
		"Name-Email: integration@example.com",
		"Expire-Date: 0",
		"%commit",
	}, "\n")

	cmd := exec.Command(gpgBin, "--batch", "--gen-key", "--pinentry-mode", "loopback")
	cmd.Env = env
	cmd.Stdin = strings.NewReader(batch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not generate throwaway gpg key (environment unsuitable): %v\n%s", err, out)
	}
	_ = home
}

func exportPublicKey(t *testing.T, gpgBin, home string, env []string) string {
	t.Helper()
	cmd := exec.Command(gpgBin, "--batch", "--armor", "--export", "integration@example.com")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("exporting public key: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("exported public key is empty")
	}
	_ = home
	return string(out)
}

func killAgent(t *testing.T, gpgBin, home string, env []string) {
	t.Helper()
	// Best-effort: stop the gpg-agent so the temp dir can be removed cleanly.
	cmd := exec.Command("gpgconf", "--kill", "gpg-agent")
	cmd.Env = env
	_ = cmd.Run()
	_, _, _ = gpgBin, home, env
}
