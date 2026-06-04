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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// gpgSignTimeout bounds the wait for the external gpg invocation, leaving
// enough time for a human to enter a PIN via pinentry while still terminating
// a stuck process.
const gpgSignTimeout = 2 * time.Minute

// signer produces an ASCII-armored detached OpenPGP signature over data.
// It returns ("", nil) when no signature should be attached.
type signer interface {
	sign(ctx context.Context, data []byte) (string, error)
}

// keyRingSigner signs in-process using a gopenpgp key ring loaded from a file.
type keyRingSigner struct {
	keyRing *crypto.KeyRing
}

// sign reproduces the historic in-process signing path: a detached signature
// over data, ASCII-armored with the OpenPGP signature header.
func (s *keyRingSigner) sign(_ context.Context, data []byte) (string, error) {
	sig, err := s.keyRing.SignDetached(crypto.NewPlainMessage(data))
	if err != nil {
		return "", err
	}
	armored, err := armor.ArmorWithTypeAndCustomHeaders(
		sig.Data, constants.PGPSignatureHeader, "", "")
	if err != nil {
		return "", err
	}
	return armored, nil
}

// gpgSigner signs by shelling out to the system gpg binary, which in turn
// delegates passphrase/PIN handling to gpg-agent/pinentry. No passphrase or
// PIN material is ever passed to or learned by the uploader.
type gpgSigner struct {
	binary    string
	localUser string
	// env, when non-nil, holds additional environment entries ("KEY=VALUE")
	// appended to the inherited process environment for the gpg invocation. It
	// exists so tests can point gpg at an ephemeral GNUPGHOME; production leaves
	// it nil and gpg inherits the uploader's environment unchanged.
	env []string
}

// sign runs the gpg binary to produce an ASCII-armored detached signature over
// data, which is fed to the process via stdin. The armored signature is read
// from stdout. On failure the captured stderr is surfaced in the returned
// error; it is never logged on success.
func (s *gpgSigner) sign(ctx context.Context, data []byte) (string, error) {
	// Bound the gpg invocation only. The timeout must leave room for a human
	// to enter a PIN via pinentry, so it is scoped here rather than around the
	// whole upload (which has its own, separate lifetime).
	ctx, cancel := context.WithTimeout(ctx, gpgSignTimeout)
	defer cancel()

	args := []string{"--batch", "--armor", "--detach-sign"}
	if s.localUser != "" {
		args = append(args, "--local-user", s.localUser)
	}
	args = append(args, "--output", "-")

	cmd := exec.CommandContext(ctx, s.binary, args...)
	if s.env != nil {
		cmd.Env = append(os.Environ(), s.env...)
	}
	cmd.Stdin = bytes.NewReader(data)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// exec.ErrNotFound covers a bare command name missing from $PATH;
		// fs.ErrNotExist covers a path (absolute or relative) that does not
		// exist, where the failure only surfaces at fork/exec.
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("gpg binary %q not found: %w", s.binary, err)
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", fmt.Errorf("gpg (%s) failed: %w: %s", s.binary, err, msg)
		}
		return "", fmt.Errorf("gpg (%s) failed: %w", s.binary, err)
	}

	if stdout.Len() == 0 {
		return "", fmt.Errorf("gpg produced an empty signature")
	}

	return stdout.String(), nil
}
