// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gocsaf/csaf/v3/internal/misc"
	"github.com/gocsaf/csaf/v3/util"
)

// failedForwardDir is the name of the special sub folder
// where advisories get stored which fail forwarding.
const failedForwardDir = "failed_forward"

// validationStatus represents the validation status
// known to the HTTP endpoint.
type validationStatus string

const (
	validValidationStatus        = validationStatus("valid")
	invalidValidationStatus      = validationStatus("invalid")
	notValidatedValidationStatus = validationStatus("not_validated")
)

func (vs *validationStatus) update(status validationStatus) {
	// Cannot heal after it fails at least once.
	if *vs != invalidValidationStatus {
		*vs = status
	}
}

// forwarder forwards downloaded advisories to a given
// HTTP endpoint.
type forwarder struct {
	cfg    *config
	cmds   chan func(*forwarder)
	client util.Client

	failed    int
	succeeded int
}

// newForwarder creates a new forwarder.
func newForwarder(cfg *config) *forwarder {
	queue := cfg.ForwardQueue
	if queue < 1 {
		queue = 1
	}
	return &forwarder{
		cfg:  cfg,
		cmds: make(chan func(*forwarder), queue),
	}
}

// run runs the forwarder. Meant to be used in a Go routine.
func (f *forwarder) run() {
	defer slog.Debug("forwarder done")

	for cmd := range f.cmds {
		cmd(f)
	}
}

// close terminates the forwarder.
func (f *forwarder) close() {
	close(f.cmds)
}

// log logs the current statistics.
func (f *forwarder) log() {
	f.cmds <- func(f *forwarder) {
		slog.Info("Forward statistics",
			"succeeded", f.succeeded,
			"failed", f.failed)
	}
}

// httpClient returns a cached HTTP client used for uploading
// the advisories to the configured HTTP endpoint.
func (f *forwarder) httpClient() util.Client {
	if f.client != nil {
		return f.client
	}

	hClient := http.Client{}

	var tlsConfig tls.Config
	if f.cfg.ForwardInsecure {
		tlsConfig.InsecureSkipVerify = true
	}

	hClient.Transport = &http.Transport{
		TLSClientConfig: &tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}

	client := util.Client(&hClient)

	// Add extra headers.
	client = &util.HeaderClient{
		Client: client,
		Header: f.cfg.ForwardHeader,
	}

	// Add optional URL logging.
	if f.cfg.verbose() {
		client = &util.LoggingClient{
			Client: client,
			Log:    httpLog("forwarder"),
		}
	}

	f.client = client
	return f.client
}

// replaceExt replaces the extension of a given filename.
func replaceExt(fname, nExt string) string {
	ext := filepath.Ext(fname)
	return fname[:len(fname)-len(ext)] + nExt
}

// buildRequest creates an HTTP request suited to forward the given advisory.
func (f *forwarder) buildRequest(
	filename, doc string,
	status validationStatus,
	sha256, sha512 string,
) (*http.Request, error) {
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	var err error
	part := func(name, fname, mimeType, content string) {
		if err != nil {
			return
		}
		if fname == "" {
			err = writer.WriteField(name, content)
			return
		}
		var w io.Writer
		if w, err = misc.CreateFormFile(writer, name, fname, mimeType); err == nil {
			_, err = w.Write([]byte(content))
		}
	}

	base := filepath.Base(filename)
	part("advisory", base, "application/json", doc)
	part("validation_status", "", "text/plain", string(status))
	if sha256 != "" {
		part("hash-256", replaceExt(base, ".sha256"), "text/plain", sha256)
	}
	if sha512 != "" {
		part("hash-512", replaceExt(base, ".sha512"), "text/plain", sha512)
	}

	if err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, f.cfg.ForwardURL, body)
	if err != nil {
		return nil, err
	}
	contentType := writer.FormDataContentType()
	req.Header.Set("Content-Type", contentType)
	return req, nil
}

// storeFailedAdvisory stores an advisory in a special folder
// in case the forwarding failed.
func (f *forwarder) storeFailedAdvisory(filename, doc, sha256, sha512 string) error {
	// Create special folder if it does not exist.
	dir := filepath.Join(f.cfg.Directory, failedForwardDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	// Store parts which are not empty.
	for _, x := range []struct {
		p string
		d string
	}{
		{filename, doc},
		{filename + ".sha256", sha256},
		{filename + ".sha512", sha512},
	} {
		if len(x.d) != 0 {
			path := filepath.Join(dir, x.p)
			if err := os.WriteFile(path, []byte(x.d), 0644); err != nil {
				return err
			}
		}
	}
	return nil
}

// storeFailed is a logging wrapper around storeFailedAdvisory.
func (f *forwarder) storeFailed(filename, doc, sha256, sha512 string) {
	f.failed++
	if err := f.storeFailedAdvisory(filename, doc, sha256, sha512); err != nil {
		slog.Error("Storing advisory failed forwarding failed",
			"error", err)
	}
}

// limitedString reads max bytes from reader and returns it as a string.
// Longer strings are indicated by "..." as a suffix.
func limitedString(r io.Reader, maxLength int) (string, error) {
	var msg strings.Builder
	if _, err := io.Copy(&msg, io.LimitReader(r, int64(maxLength))); err != nil {
		return "", err
	}
	if msg.Len() >= maxLength {
		msg.WriteString("...")
	}
	return msg.String(), nil
}

// forward sends a given document with filename, status and
// checksums to the forwarder. This is async to the degree
// till the configured queue size is filled.
func (f *forwarder) forward(
	filename, doc string,
	status validationStatus,
	sha256, sha512 string,
) {
	// Run this in the main loop of the forwarder.
	f.cmds <- func(f *forwarder) {
		req, err := f.buildRequest(filename, doc, status, sha256, sha512)
		if err != nil {
			slog.Error("building forward Request failed",
				"error", err)
			f.storeFailed(filename, doc, sha256, sha512)
			return
		}
		res, err := f.httpClient().Do(req)
		if err != nil {
			slog.Error("sending forward request failed",
				"error", err)
			f.storeFailed(filename, doc, sha256, sha512)
			return
		}
		if res.StatusCode != http.StatusCreated {
			defer res.Body.Close()
			if msg, err := limitedString(res.Body, 512); err != nil {
				slog.Error("reading forward result failed",
					"error", err)
			} else {
				slog.Error("forwarding failed",
					"filename", filename,
					"body", msg,
					"status_code", res.StatusCode)
			}
			f.storeFailed(filename, doc, sha256, sha512)
		} else {
			f.succeeded++
			slog.Debug(
				"forwarding succeeded",
				"filename", filename)
		}
	}
}
