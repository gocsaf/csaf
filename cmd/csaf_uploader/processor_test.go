// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// buildGo compiles src into bin using the local go toolchain. It is shared by
// the signer stub tests (signer_test.go) and is offline because the compiled
// sources only use the standard library.
func buildGo(t *testing.T, bin, src string) (string, error) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", bin, src)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// minimalCSAF is a tiny well-formed JSON object. The multipart tests run with
// NoSchemaCheck=true so the content does not need to be a valid CSAF advisory;
// only the bytes-on-the-wire matter here.
const minimalCSAF = `{"document":{"title":"test"}}`

// writeCSAFFile writes a conforming-named CSAF file into a temp dir and returns
// its path. The provider's ConformingFileName check is bypassed because the
// tests call uploadRequest directly, but a JSON-safe name keeps things tidy.
func writeCSAFFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("writing CSAF file: %v", err)
	}
	return p
}

// parseMultipart parses an http.Request produced by uploadRequest and returns a
// map of field name to value for the simple (non-file) and file fields.
func parseMultipart(t *testing.T, p *processor, filename string) map[string]string {
	t.Helper()

	req, err := p.uploadRequest(context.Background(), filename)
	if err != nil {
		t.Fatalf("uploadRequest() error: %v", err)
	}

	_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parsing content-type: %v", err)
	}
	boundary := params["boundary"]
	if boundary == "" {
		t.Fatalf("no multipart boundary in content-type %q", req.Header.Get("Content-Type"))
	}

	mr := multipart.NewReader(req.Body, boundary)
	fields := map[string]string{}
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, part); err != nil {
			t.Fatalf("reading part %q: %v", part.FormName(), err)
		}
		fields[part.FormName()] = buf.String()
	}
	return fields
}

// newTestConfig returns a config suitable for uploadRequest unit tests:
// schema check disabled, sensible defaults.
func newTestConfig() *config {
	return &config{
		URL:           defaultURL,
		TLP:           defaultTLP,
		Action:        defaultAction,
		NoSchemaCheck: true,
	}
}

// TestUploadRequestNoSigner covers acceptance criterion 1 / disposition 1: with
// no signer and a passphrase set, the multipart body carries a passphrase field
// and no signature field (the pre-change baseline behavior).
func TestUploadRequestNoSignerWithPassphrase(t *testing.T) {
	dir := t.TempDir()
	file := writeCSAFFile(t, dir, "doc.json", minimalCSAF)

	pass := "s3cret"
	cfg := newTestConfig()
	cfg.Passphrase = &pass

	// no key, no gpg -> nil signer (cfg.signer left unset).

	fields := parseMultipart(t, &processor{cfg: cfg}, file)

	if fields["csaf"] != minimalCSAF {
		t.Errorf("csaf field = %q, want %q", fields["csaf"], minimalCSAF)
	}
	if fields["tlp"] != defaultTLP {
		t.Errorf("tlp field = %q, want %q", fields["tlp"], defaultTLP)
	}
	if got, ok := fields["passphrase"]; !ok || got != pass {
		t.Errorf("passphrase field = %q (present=%v), want %q present", got, ok, pass)
	}
	if _, ok := fields["signature"]; ok {
		t.Errorf("signature field present, want absent in no-signer mode")
	}
}

// TestUploadRequestKeyRingSigner covers disposition 2: a key-ring signer writes
// a real armored detached signature into the signature field and no passphrase.
func TestUploadRequestKeyRingSigner(t *testing.T) {
	dir := t.TempDir()
	file := writeCSAFFile(t, dir, "doc.json", minimalCSAF)

	keyRing := newTestKeyRing(t)

	pass := "ignored-when-signing"
	cfg := newTestConfig()
	cfg.Passphrase = &pass
	cfg.signer = &keyRingSigner{keyRing: keyRing}

	fields := parseMultipart(t, &processor{cfg: cfg}, file)

	sig, ok := fields["signature"]
	if !ok || sig == "" {
		t.Fatalf("signature field missing/empty, want armored signature")
	}
	if !strings.Contains(sig, "BEGIN PGP SIGNATURE") {
		t.Errorf("signature field is not an armored PGP signature: %q", sig)
	}
	if _, ok := fields["passphrase"]; ok {
		t.Errorf("passphrase field present, want suppressed when a signer is active")
	}

	// The signature must verify against the uploaded bytes.
	verifyDetached(t, keyRing, []byte(minimalCSAF), sig)
}

// TestUploadRequestGPGSigner covers criterion 4: the gpg signer's stdout is
// written verbatim into the signature field and no passphrase field is written,
// even though a passphrase is configured (it must never reach gpg mode output).
func TestUploadRequestGPGSigner(t *testing.T) {
	dir := t.TempDir()
	file := writeCSAFFile(t, dir, "doc.json", minimalCSAF)

	const armored = "-----BEGIN PGP SIGNATURE-----\n\nGPGSTUBOUTPUT\n-----END PGP SIGNATURE-----\n"

	// Point gpg mode at the deterministic stub binary. The gpg argv/stdin
	// contract itself is covered in signer_test.go; here we drive the real
	// gpgSigner through uploadRequest to test multipart composition and that
	// the uploaded bytes reach gpg's stdin.
	bin := buildStubGPG(t)
	stdinFile := filepath.Join(dir, "stdin")
	t.Setenv("STUB_STDIN_FILE", stdinFile)
	t.Setenv("STUB_STDOUT", armored)

	cfg := newTestConfig()
	pass := "must-not-appear"
	cfg.Passphrase = &pass
	cfg.signer = &gpgSigner{binary: bin}

	fields := parseMultipart(t, &processor{cfg: cfg}, file)

	if got := fields["signature"]; got != armored {
		t.Errorf("signature field = %q, want verbatim gpg output %q", got, armored)
	}
	if _, ok := fields["passphrase"]; ok {
		t.Errorf("passphrase field present, want never written in gpg/signer mode")
	}
	gotStdin, err := os.ReadFile(stdinFile)
	if err != nil {
		t.Fatalf("reading captured stdin: %v", err)
	}
	if string(gotStdin) != minimalCSAF {
		t.Errorf("gpg received %q, want the uploaded bytes %q", gotStdin, minimalCSAF)
	}
}

// TestUploadRequestExternalSigned covers disposition 3: the contents of the
// adjacent .asc file become the signature field. External-signed mode produces
// a nil signer, so the passphrase field follows the same guard as the no-signer
// baseline (cfg.signer == nil && cfg.Passphrase != nil): present iff a
// passphrase is configured. This matches the pre-feature behavior exactly, where
// the original guard (no key ring loaded) wrote the passphrase field in
// external-signed mode.
func TestUploadRequestExternalSigned(t *testing.T) {
	const asc = "-----BEGIN PGP SIGNATURE-----\n\nEXTERNALSIG\n-----END PGP SIGNATURE-----\n"

	tests := []struct {
		name          string
		passphrase    *string
		wantPass      bool
		wantPassValue string
	}{
		{
			name:       "without passphrase",
			passphrase: nil,
			wantPass:   false,
		},
		{
			name:          "with passphrase",
			passphrase:    func() *string { s := "s3cret"; return &s }(),
			wantPass:      true,
			wantPassValue: "s3cret",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			file := writeCSAFFile(t, dir, "doc.json", minimalCSAF)
			if err := os.WriteFile(file+".asc", []byte(asc), 0o600); err != nil {
				t.Fatalf("writing .asc: %v", err)
			}

			cfg := newTestConfig()
			cfg.ExternalSigned = true
			cfg.Passphrase = tc.passphrase
			// external-signed => nil signer (cfg.signer left unset).

			fields := parseMultipart(t, &processor{cfg: cfg}, file)

			if got := fields["signature"]; got != asc {
				t.Errorf("signature field = %q, want .asc contents %q", got, asc)
			}

			got, ok := fields["passphrase"]
			if ok != tc.wantPass {
				t.Errorf("passphrase field present=%v, want present=%v "+
					"(external-signed keeps the baseline nil-signer guard)", ok, tc.wantPass)
			}
			if tc.wantPass && got != tc.wantPassValue {
				t.Errorf("passphrase field = %q, want %q", got, tc.wantPassValue)
			}
		})
	}
}

// --- helpers for OpenPGP key generation / verification -------------------

// newTestKeyRing builds an in-memory throwaway OpenPGP key ring for signing.
func newTestKeyRing(t *testing.T) *crypto.KeyRing {
	t.Helper()
	key, err := crypto.GenerateKey("csaf tester", "tester@example.com", "rsa", 2048)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	ring, err := crypto.NewKeyRing(key)
	if err != nil {
		t.Fatalf("building key ring: %v", err)
	}
	return ring
}

// verifyDetached asserts that armoredSig is a valid detached signature over
// data, using the same gopenpgp path the server uses.
func verifyDetached(t *testing.T, ring *crypto.KeyRing, data []byte, armoredSig string) {
	t.Helper()
	pgpSig, err := crypto.NewPGPSignatureFromArmored(armoredSig)
	if err != nil {
		t.Fatalf("parsing armored signature: %v", err)
	}
	if err := ring.VerifyDetached(
		crypto.NewPlainMessage(data), pgpSig, crypto.GetUnixTime(),
	); err != nil {
		t.Fatalf("VerifyDetached failed: %v", err)
	}
}
