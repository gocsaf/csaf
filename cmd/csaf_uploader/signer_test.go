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
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// stubGPGSource is a tiny standalone program compiled at test time and used as
// a fake gpg binary. It records its argv and the bytes it received on stdin to
// files, then emits a configurable stdout / stderr and exits with a
// configurable status. Behavior is driven by environment variables so a single
// compiled binary serves every test case.
//
//	STUB_ARGS_FILE   path to write the JSON-ish argv dump to (one arg per line)
//	STUB_STDIN_FILE  path to write the received stdin bytes to
//	STUB_STDOUT      literal text to write to stdout
//	STUB_STDERR      literal text to write to stderr
//	STUB_EXIT        exit code (default 0)
const stubGPGSource = `package main

import (
	"io"
	"os"
	"strconv"
	"strings"
)

func main() {
	if f := os.Getenv("STUB_ARGS_FILE"); f != "" {
		_ = os.WriteFile(f, []byte(strings.Join(os.Args[1:], "\n")), 0o600)
	}
	if f := os.Getenv("STUB_STDIN_FILE"); f != "" {
		data, _ := io.ReadAll(os.Stdin)
		_ = os.WriteFile(f, data, 0o600)
	}
	if s := os.Getenv("STUB_STDOUT"); s != "" {
		_, _ = os.Stdout.WriteString(s)
	}
	if s := os.Getenv("STUB_STDERR"); s != "" {
		_, _ = os.Stderr.WriteString(s)
	}
	code := 0
	if s := os.Getenv("STUB_EXIT"); s != "" {
		code, _ = strconv.Atoi(s)
	}
	os.Exit(code)
}
`

// buildStubGPG compiles the stub program once per test and returns the path to
// the resulting executable inside a temp dir. The build is fully local; no
// network or module download is required because the stub has no imports
// outside the standard library.
func buildStubGPG(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	src := filepath.Join(dir, "stubgpg.go")
	if err := os.WriteFile(src, []byte(stubGPGSource), 0o600); err != nil {
		t.Fatalf("writing stub source: %v", err)
	}

	bin := filepath.Join(dir, "stubgpg")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	// go build of a single self-contained file is offline and deterministic.
	if out, err := buildGo(t, bin, src); err != nil {
		t.Fatalf("building stub gpg: %v\n%s", err, out)
	}
	return bin
}

// TestGPGSignerArgsAndStdin covers criteria 5 and 6: the args passed to gpg and
// the document delivered via stdin, plus stdout passthrough (criterion 4 at the
// signer level). It runs both with and without a configured local-user.
func TestGPGSignerArgsAndStdin(t *testing.T) {
	bin := buildStubGPG(t)

	const armored = "-----BEGIN PGP SIGNATURE-----\n\nSTUBSIG\n-----END PGP SIGNATURE-----\n"
	doc := []byte(`{"document":"hello"}`)

	tests := []struct {
		name      string
		localUser string
		wantUser  bool
	}{
		{name: "without local-user", localUser: ""},
		{name: "with local-user", localUser: "0xDEADBEEF", wantUser: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			argsFile := filepath.Join(dir, "args")
			stdinFile := filepath.Join(dir, "stdin")

			t.Setenv("STUB_ARGS_FILE", argsFile)
			t.Setenv("STUB_STDIN_FILE", stdinFile)
			t.Setenv("STUB_STDOUT", armored)
			t.Setenv("STUB_STDERR", "")
			t.Setenv("STUB_EXIT", "")

			s := &gpgSigner{binary: bin, localUser: tt.localUser}
			got, err := s.sign(context.Background(), doc)
			if err != nil {
				t.Fatalf("sign() unexpected error: %v", err)
			}

			// stdout is returned verbatim.
			if got != armored {
				t.Fatalf("sign() = %q, want %q", got, armored)
			}

			// stdin equals the document bytes exactly.
			gotStdin, err := os.ReadFile(stdinFile)
			if err != nil {
				t.Fatalf("reading captured stdin: %v", err)
			}
			if string(gotStdin) != string(doc) {
				t.Fatalf("stdin = %q, want %q", gotStdin, doc)
			}

			// argv assertions.
			rawArgs, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatalf("reading captured args: %v", err)
			}
			args := strings.Split(strings.TrimSpace(string(rawArgs)), "\n")
			argsJoined := strings.Join(args, " ")

			for _, want := range []string{"--detach-sign", "--armor"} {
				if !containsArg(args, want) {
					t.Errorf("args %v missing %q", args, want)
				}
			}
			// --output - present and adjacent.
			if !containsPair(args, "--output", "-") {
				t.Errorf("args %v missing %q %q pair", args, "--output", "-")
			}

			// --local-user present iff configured, with the expected value.
			if tt.wantUser {
				if !containsPair(args, "--local-user", tt.localUser) {
					t.Errorf("args %v missing %q %q pair", args, "--local-user", tt.localUser)
				}
			} else if containsArg(args, "--local-user") {
				t.Errorf("args %v unexpectedly contain --local-user", args)
			}

			// Never any passphrase / PIN / loopback material.
			forbidden := []string{
				"--passphrase",
				"--passphrase-fd",
				"--passphrase-file",
				"--pinentry-mode",
				"loopback",
			}
			for _, f := range forbidden {
				if strings.Contains(argsJoined, f) {
					t.Errorf("args %v unexpectedly contain forbidden token %q", args, f)
				}
			}
		})
	}
}

// TestGPGSignerNonZeroExit covers criterion 7: a non-zero gpg exit returns an
// error that includes the captured stderr text.
func TestGPGSignerNonZeroExit(t *testing.T) {
	bin := buildStubGPG(t)

	const stderrMsg = "gpg: signing failed: No secret key"
	t.Setenv("STUB_STDOUT", "")
	t.Setenv("STUB_STDERR", stderrMsg)
	t.Setenv("STUB_EXIT", "2")

	s := &gpgSigner{binary: bin}
	_, err := s.sign(context.Background(), []byte("data"))
	if err == nil {
		t.Fatal("sign() = nil error, want failure")
	}
	if !strings.Contains(err.Error(), stderrMsg) {
		t.Fatalf("sign() error %q does not contain stderr %q", err.Error(), stderrMsg)
	}
}

// TestGPGSignerEmptyStdout covers criterion 8: exit 0 with empty stdout yields a
// descriptive error rather than an empty signature.
func TestGPGSignerEmptyStdout(t *testing.T) {
	bin := buildStubGPG(t)

	t.Setenv("STUB_STDOUT", "")
	t.Setenv("STUB_STDERR", "")
	t.Setenv("STUB_EXIT", "0")

	s := &gpgSigner{binary: bin}
	got, err := s.sign(context.Background(), []byte("data"))
	if err == nil {
		t.Fatalf("sign() = %q, nil error; want descriptive empty-signature error", got)
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("sign() error %q does not describe an empty signature", err.Error())
	}
}

// TestGPGSignerBinaryNotFound covers criterion 9: a non-existent binary yields a
// clear not-found error naming the configured binary. Both forms are exercised
// because they fail through different paths: a bare command name missing from
// $PATH surfaces exec.ErrNotFound at construction, while a path that does not
// exist surfaces fs.ErrNotExist only at fork/exec.
func TestGPGSignerBinaryNotFound(t *testing.T) {
	tests := []struct {
		name   string
		binary string
	}{
		{name: "bare name missing from PATH", binary: "gpg-definitely-not-installed-xyz"},
		{name: "absolute path that does not exist", binary: "/nonexistent/path/to/gpg-does-not-exist"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &gpgSigner{binary: tt.binary}
			_, err := s.sign(context.Background(), []byte("data"))
			if err == nil {
				t.Fatal("sign() = nil error, want not-found failure")
			}
			if !strings.Contains(err.Error(), tt.binary) {
				t.Fatalf("sign() error %q does not name the binary %q", err.Error(), tt.binary)
			}
			if !strings.Contains(err.Error(), "not found") {
				t.Fatalf("sign() error %q is not the dedicated not-found message", err.Error())
			}
		})
	}
}

// TestGPGSignTimeoutConstant guards the documented default timeout so an
// accidental change is noticed.
func TestGPGSignTimeoutConstant(t *testing.T) {
	if gpgSignTimeout != 2*time.Minute {
		t.Fatalf("gpgSignTimeout = %v, want %v", gpgSignTimeout, 2*time.Minute)
	}
}

// containsArg reports whether args contains exactly token.
func containsArg(args []string, token string) bool {
	for _, a := range args {
		if a == token {
			return true
		}
	}
	return false
}

// containsPair reports whether args contains flag immediately followed by value.
func containsPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}
