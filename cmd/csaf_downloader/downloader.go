// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022, 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022, 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"golang.org/x/time/rate"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

type hashFetchInfo struct {
	url       string
	preferred bool
	warn      bool
	hashType  hashAlgorithm
}

type downloader struct {
	cfg       *config
	client    *util.Client // Used for testing
	keys      *crypto.KeyRing
	validator csaf.RemoteValidator
	forwarder *forwarder
	mkdirMu   sync.Mutex
	statsMu   sync.Mutex
	stats     stats
}

// failedValidationDir is the name of the sub folder
// where advisories are stored that fail validation in
// unsafe mode.
const failedValidationDir = "failed_validation"

func newDownloader(cfg *config) (*downloader, error) {
	var validator csaf.RemoteValidator

	if cfg.RemoteValidator != "" {
		validatorOptions := csaf.RemoteValidatorOptions{
			URL:     cfg.RemoteValidator,
			Presets: cfg.RemoteValidatorPresets,
			Cache:   cfg.RemoteValidatorCache,
		}
		var err error
		if validator, err = validatorOptions.Open(); err != nil {
			return nil, fmt.Errorf(
				"preparing remote validator failed: %w", err)
		}
		validator = csaf.SynchronizedRemoteValidator(validator)
	}

	return &downloader{
		cfg:       cfg,
		validator: validator,
	}, nil
}

func (d *downloader) close() {
	if d.validator != nil {
		d.validator.Close()
		d.validator = nil
	}
}

// addStats add stats to total stats
func (d *downloader) addStats(o *stats) {
	d.statsMu.Lock()
	defer d.statsMu.Unlock()
	d.stats.add(o)
}

// logRedirect logs redirects of the http client.
func logRedirect(req *http.Request, via []*http.Request) error {
	vs := make([]string, len(via))
	for i, v := range via {
		vs[i] = v.URL.String()
	}
	slog.Debug("Redirecting",
		"to", req.URL.String(),
		"via", strings.Join(vs, " -> "))
	return nil
}

func (d *downloader) httpClient() util.Client {
	hClient := http.Client{}

	if d.cfg.verbose() {
		hClient.CheckRedirect = logRedirect
	}

	var tlsConfig tls.Config
	if d.cfg.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if len(d.cfg.clientCerts) != 0 {
		tlsConfig.Certificates = d.cfg.clientCerts
	}

	hClient.Transport = &http.Transport{
		TLSClientConfig: &tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}

	client := util.Client(&hClient)

	// Overwrite for testing purposes
	if d.client != nil {
		client = *d.client
	}

	// Add extra headers.
	client = &util.HeaderClient{
		Client: client,
		Header: d.cfg.ExtraHeader,
	}

	// Add optional URL logging.
	if d.cfg.verbose() {
		client = &util.LoggingClient{
			Client: client,
			Log:    httpLog("downloader"),
		}
	}

	// Add optional rate limiting.
	if d.cfg.Rate != nil {
		client = &util.LimitingClient{
			Client:  client,
			Limiter: rate.NewLimiter(rate.Limit(*d.cfg.Rate), 1),
		}
	}

	return client
}

// httpLog does structured logging in a [util.LoggingClient].
func httpLog(who string) func(string, string) {
	return func(method, url string) {
		slog.Debug("http",
			"who", who,
			"method", method,
			"url", url)
	}
}

func (d *downloader) enumerate(domain string) error {
	client := d.httpClient()

	loader := csaf.NewProviderMetadataLoader(client)
	lpmd := loader.Enumerate(domain)

	docs := []any{}

	for _, pmd := range lpmd {
		if d.cfg.verbose() {
			for i := range pmd.Messages {
				slog.Debug("Enumerating provider-metadata.json",
					"domain", domain,
					"message", pmd.Messages[i].Message)
			}
		}

		docs = append(docs, pmd.Document)
	}

	// print the results
	doc, err := json.MarshalIndent(docs, "", "  ")
	if err != nil {
		slog.Error("Couldn't marshal PMD document json")
	}
	fmt.Println(string(doc))

	return nil
}

func (d *downloader) download(ctx context.Context, domain string) error {
	client := d.httpClient()

	loader := csaf.NewProviderMetadataLoader(client)

	lpmd := loader.Load(domain)

	if !lpmd.Valid() {
		for i := range lpmd.Messages {
			slog.Error("Loading provider-metadata.json",
				"domain", domain,
				"message", lpmd.Messages[i].Message)
		}
		return fmt.Errorf("no valid provider-metadata.json found for '%s'", domain)
	} else if d.cfg.verbose() {
		for i := range lpmd.Messages {
			slog.Debug("Loading provider-metadata.json",
				"domain", domain,
				"message", lpmd.Messages[i].Message)
		}
	}

	base, err := url.Parse(lpmd.URL)
	if err != nil {
		return fmt.Errorf("invalid URL '%s': %v", lpmd.URL, err)
	}

	expr := util.NewPathEval()

	if err := d.loadOpenPGPKeys(
		client,
		lpmd.Document,
		base,
		expr,
	); err != nil {
		return err
	}

	afp := csaf.NewAdvisoryFileProcessor(
		client,
		expr,
		lpmd.Document,
		base)

	// Do we need time range based filtering?
	if d.cfg.Range != nil {
		slog.Debug("Setting up filter to accept advisories within",
			"timerange", d.cfg.Range)
		afp.AgeAccept = d.cfg.Range.Contains
	}

	return afp.Process(func(label csaf.TLPLabel, files []csaf.AdvisoryFile) error {
		return d.downloadFiles(ctx, label, files)
	})
}

func (d *downloader) downloadFiles(
	ctx context.Context,
	label csaf.TLPLabel,
	files []csaf.AdvisoryFile,
) error {
	var (
		advisoryCh = make(chan csaf.AdvisoryFile)
		errorCh    = make(chan error)
		errDone    = make(chan struct{})
		errs       []error
		wg         sync.WaitGroup
	)

	// collect errors
	go func() {
		defer close(errDone)
		for err := range errorCh {
			errs = append(errs, err)
		}
	}()

	var n int
	if n = d.cfg.Worker; n < 1 {
		n = 1
	}

	for i := 0; i < n; i++ {
		wg.Add(1)
		go d.downloadWorker(ctx, &wg, label, advisoryCh, errorCh)
	}

allFiles:
	for _, file := range files {
		select {
		case advisoryCh <- file:
		case <-ctx.Done():
			break allFiles
		}
	}

	close(advisoryCh)
	wg.Wait()
	close(errorCh)
	<-errDone

	return errors.Join(errs...)
}

func (d *downloader) loadOpenPGPKeys(
	client util.Client,
	doc any,
	base *url.URL,
	expr *util.PathEval,
) error {
	src, err := expr.Eval("$.public_openpgp_keys", doc)
	if err != nil {
		// no keys.
		return nil
	}

	var keys []csaf.PGPKey
	if err := util.ReMarshalJSON(&keys, src); err != nil {
		return err
	}

	if len(keys) == 0 {
		return nil
	}

	// Try to load

	for i := range keys {
		key := &keys[i]
		if key.URL == nil {
			continue
		}
		up, err := url.Parse(*key.URL)
		if err != nil {
			slog.Warn("Invalid URL",
				"url", *key.URL,
				"error", err)
			continue
		}

		u := base.ResolveReference(up).String()

		res, err := client.Get(u)
		if err != nil {
			slog.Warn(
				"Fetching public OpenPGP key failed",
				"url", u,
				"error", err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			slog.Warn(
				"Fetching public OpenPGP key failed",
				"url", u,
				"status_code", res.StatusCode,
				"status", res.Status)
			continue
		}

		ckey, err := func() (*crypto.Key, error) {
			defer res.Body.Close()
			return crypto.NewKeyFromArmoredReader(res.Body)
		}()
		if err != nil {
			slog.Warn(
				"Reading public OpenPGP key failed",
				"url", u,
				"error", err)
			continue
		}

		if !strings.EqualFold(ckey.GetFingerprint(), string(key.Fingerprint)) {
			slog.Warn(
				"Fingerprint of public OpenPGP key does not match remotely loaded",
				"url", u, "fingerprint", key.Fingerprint, "remote-fingerprint", ckey.GetFingerprint())
			continue
		}
		if d.keys == nil {
			if keyring, err := crypto.NewKeyRing(ckey); err != nil {
				slog.Warn(
					"Creating store for public OpenPGP key failed",
					"url", u,
					"error", err)
			} else {
				d.keys = keyring
			}
		} else {
			d.keys.AddKey(ckey)
		}
	}
	return nil
}

// logValidationIssues logs the issues reported by the advisory schema validation.
func (d *downloader) logValidationIssues(url string, errors []string, err error) {
	if err != nil {
		slog.Error("Failed to validate",
			"url", url,
			"error", err)
		return
	}
	if len(errors) > 0 {
		if d.cfg.verbose() {
			slog.Error("CSAF file has validation errors",
				"url", url,
				"error", strings.Join(errors, ", "))
		} else {
			slog.Error("CSAF file has validation errors",
				"url", url,
				"count", len(errors))
		}
	}
}

func (d *downloader) downloadWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	label csaf.TLPLabel,
	files <-chan csaf.AdvisoryFile,
	errorCh chan<- error,
) {
	defer wg.Done()

	var (
		client             = d.httpClient()
		data               bytes.Buffer
		lastDir            string
		initialReleaseDate time.Time
		dateExtract        = util.TimeMatcher(&initialReleaseDate, time.RFC3339)
		lower              = strings.ToLower(string(label))
		stats              = stats{}
		expr               = util.NewPathEval()
	)

	// Add collected stats back to total.
	defer d.addStats(&stats)

nextAdvisory:
	for {
		var file csaf.AdvisoryFile
		var ok bool
		select {
		case file, ok = <-files:
			if !ok {
				return
			}
		case <-ctx.Done():
			return
		}

		u, err := url.Parse(file.URL())
		if err != nil {
			stats.downloadFailed++
			slog.Warn("Ignoring invalid URL",
				"url", file.URL(),
				"error", err)
			continue
		}

		if d.cfg.ignoreURL(file.URL()) {
			slog.Debug("Ignoring URL", "url", file.URL())
			continue
		}

		// Ignore not conforming filenames.
		filename := filepath.Base(u.Path)
		if !util.ConformingFileName(filename) {
			stats.filenameFailed++
			slog.Warn("Ignoring none conforming filename",
				"filename", filename)
			continue
		}

		resp, err := client.Get(file.URL())
		if err != nil {
			stats.downloadFailed++
			slog.Warn("Cannot GET",
				"url", file.URL(),
				"error", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			stats.downloadFailed++
			slog.Warn("Cannot load",
				"url", file.URL(),
				"status", resp.Status,
				"status_code", resp.StatusCode)
			continue
		}

		// Warn if we do not get JSON.
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			slog.Warn("Content type is not 'application/json'",
				"url", file.URL(),
				"content_type", ct)
		}

		var (
			writers                    []io.Writer
			s256, s512                 hash.Hash
			s256Data, s512Data         []byte
			remoteSHA256, remoteSHA512 []byte
			signData                   []byte
		)

		hashToFetch := []hashFetchInfo{}
		if file.SHA512URL() != "" {
			hashToFetch = append(hashToFetch, hashFetchInfo{
				url:       file.SHA512URL(),
				warn:      true,
				hashType:  algSha512,
				preferred: strings.EqualFold(string(d.cfg.PreferredHash), string(algSha512)),
			})
		} else {
			slog.Info("SHA512 not present")
		}
		if file.SHA256URL() != "" {
			hashToFetch = append(hashToFetch, hashFetchInfo{
				url:       file.SHA256URL(),
				warn:      true,
				hashType:  algSha256,
				preferred: strings.EqualFold(string(d.cfg.PreferredHash), string(algSha256)),
			})
		} else {
			slog.Info("SHA256 not present")
		}
		if file.IsDirectory() {
			for i := range hashToFetch {
				hashToFetch[i].warn = false
			}
		}

		remoteSHA256, s256Data, remoteSHA512, s512Data = loadHashes(client, hashToFetch)
		if remoteSHA512 != nil {
			s512 = sha512.New()
			writers = append(writers, s512)
		}
		if remoteSHA256 != nil {
			s256 = sha256.New()
			writers = append(writers, s256)
		}

		// Remember the data as we need to store it to file later.
		data.Reset()
		writers = append(writers, &data)

		// Download the advisory and hash it.
		hasher := io.MultiWriter(writers...)

		var doc any

		if err := func() error {
			defer resp.Body.Close()
			tee := io.TeeReader(resp.Body, hasher)
			return json.NewDecoder(tee).Decode(&doc)
		}(); err != nil {
			stats.downloadFailed++
			slog.Warn("Downloading failed",
				"url", file.URL(),
				"error", err)
			continue
		}

		// Compare the checksums.
		s256Check := func() error {
			if s256 != nil && !bytes.Equal(s256.Sum(nil), remoteSHA256) {
				stats.sha256Failed++
				return fmt.Errorf("SHA256 checksum of %s does not match", file.URL())
			}
			return nil
		}

		s512Check := func() error {
			if s512 != nil && !bytes.Equal(s512.Sum(nil), remoteSHA512) {
				stats.sha512Failed++
				return fmt.Errorf("SHA512 checksum of %s does not match", file.URL())
			}
			return nil
		}

		// Validate OpenPGP signature.
		keysCheck := func() error {
			// Only check signature if we have loaded keys.
			if d.keys == nil {
				return nil
			}
			var sign *crypto.PGPSignature
			sign, signData, err = loadSignature(client, file.SignURL())
			if err != nil {
				slog.Warn("Downloading signature failed",
					"url", file.SignURL(),
					"error", err)
			}
			if sign != nil {
				if err := d.checkSignature(data.Bytes(), sign); err != nil {
					if !d.cfg.IgnoreSignatureCheck {
						stats.signatureFailed++
						return fmt.Errorf("cannot verify signature for %s: %v", file.URL(), err)
					}
				}
			}
			return nil
		}

		// Validate against CSAF schema.
		schemaCheck := func() error {
			if errors, err := csaf.ValidateCSAF(doc); err != nil || len(errors) > 0 {
				stats.schemaFailed++
				d.logValidationIssues(file.URL(), errors, err)
				return fmt.Errorf("schema validation for %q failed", file.URL())
			}
			return nil
		}

		// Validate if filename is conforming.
		filenameCheck := func() error {
			if err := util.IDMatchesFilename(expr, doc, filename); err != nil {
				stats.filenameFailed++
				return fmt.Errorf("filename not conforming %s: %s", file.URL(), err)
			}
			return nil
		}

		// Validate against remote validator.
		remoteValidatorCheck := func() error {
			if d.validator == nil {
				return nil
			}
			rvr, err := d.validator.Validate(doc)
			if err != nil {
				errorCh <- fmt.Errorf(
					"calling remote validator on %q failed: %w",
					file.URL(), err)
				return nil
			}
			if !rvr.Valid {
				stats.remoteFailed++
				return fmt.Errorf("remote validation of %q failed", file.URL())
			}
			return nil
		}

		// Run all the validations.
		valStatus := notValidatedValidationStatus
		for _, check := range []func() error{
			s256Check,
			s512Check,
			keysCheck,
			schemaCheck,
			filenameCheck,
			remoteValidatorCheck,
		} {
			if err := check(); err != nil {
				slog.Error("Validation check failed", "error", err)
				valStatus.update(invalidValidationStatus)
				if d.cfg.ValidationMode == validationStrict {
					continue nextAdvisory
				}
			}
		}
		valStatus.update(validValidationStatus)

		// Send to forwarder
		if d.forwarder != nil {
			d.forwarder.forward(
				filename, data.String(),
				valStatus,
				string(s256Data),
				string(s512Data))
		}

		if d.cfg.NoStore {
			// Do not write locally.
			if valStatus == validValidationStatus {
				stats.succeeded++
			}
			continue
		}

		if err := expr.Extract(
			`$.document.tracking.initial_release_date`, dateExtract, false, doc,
		); err != nil {
			slog.Warn("Cannot extract initial_release_date from advisory",
				"url", file.URL())
			initialReleaseDate = time.Now()
		}
		initialReleaseDate = initialReleaseDate.UTC()

		// Advisories that failed validation are stored in a special folder.
		var newDir string
		if valStatus != validValidationStatus {
			newDir = path.Join(d.cfg.Directory, failedValidationDir)
		} else {
			newDir = d.cfg.Directory
		}

		// Do we have a configured destination folder?
		if d.cfg.Folder != "" {
			newDir = path.Join(newDir, d.cfg.Folder)
		} else {
			newDir = path.Join(newDir, lower, strconv.Itoa(initialReleaseDate.Year()))
		}

		if newDir != lastDir {
			if err := d.mkdirAll(newDir, 0755); err != nil {
				errorCh <- err
				continue
			}
			lastDir = newDir
		}

		// Write advisory to file
		path := filepath.Join(lastDir, filename)

		// Write data to disk.
		for _, x := range []struct {
			p string
			d []byte
		}{
			{path, data.Bytes()},
			{path + ".sha256", s256Data},
			{path + ".sha512", s512Data},
			{path + ".asc", signData},
		} {
			if x.d != nil {
				if err := os.WriteFile(x.p, x.d, 0644); err != nil {
					errorCh <- err
					continue nextAdvisory
				}
			}
		}

		stats.succeeded++
		slog.Info("Written advisory", "path", path)
	}
}

func (d *downloader) mkdirAll(path string, perm os.FileMode) error {
	d.mkdirMu.Lock()
	defer d.mkdirMu.Unlock()
	return os.MkdirAll(path, perm)
}

func (d *downloader) checkSignature(data []byte, sign *crypto.PGPSignature) error {
	pm := crypto.NewPlainMessage(data)
	t := crypto.GetUnixTime()
	return d.keys.VerifyDetached(pm, sign, t)
}

func loadSignature(client util.Client, p string) (*crypto.PGPSignature, []byte, error) {
	resp, err := client.Get(p)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf(
			"fetching signature from '%s' failed: %s (%d)", p, resp.Status, resp.StatusCode)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	sign, err := crypto.NewPGPSignatureFromArmored(string(data))
	if err != nil {
		return nil, nil, err
	}
	return sign, data, nil
}

func loadHashes(client util.Client, hashes []hashFetchInfo) ([]byte, []byte, []byte, []byte) {
	var remoteSha256, remoteSha512, sha256Data, sha512Data []byte

	// Load preferred hashes first
	slices.SortStableFunc(hashes, func(a, b hashFetchInfo) int {
		if a.preferred == b.preferred {
			return 0
		}
		if a.preferred && !b.preferred {
			return -1
		}
		return 1
	})
	for _, h := range hashes {
		if remote, data, err := loadHash(client, h.url); err != nil {
			if h.warn {
				slog.Warn("Cannot fetch hash",
					"hash", h.hashType,
					"url", h.url,
					"error", err)
			} else {
				slog.Info("Hash not present", "hash", h.hashType, "file", h.url)
			}
		} else {
			switch h.hashType {
			case algSha512:
				{
					remoteSha512 = remote
					sha512Data = data
				}
			case algSha256:
				{
					remoteSha256 = remote
					sha256Data = data
				}
			}
			if h.preferred {
				break
			}
		}
	}
	return remoteSha256, sha256Data, remoteSha512, sha512Data
}

func loadHash(client util.Client, p string) ([]byte, []byte, error) {
	resp, err := client.Get(p)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf(
			"fetching hash from '%s' failed: %s (%d)", p, resp.Status, resp.StatusCode)
	}
	defer resp.Body.Close()
	var data bytes.Buffer
	tee := io.TeeReader(resp.Body, &data)
	hash, err := util.HashFromReader(tee)
	if err != nil {
		return nil, nil, err
	}
	return hash, data.Bytes(), nil
}

// run performs the downloads for all the given domains.
func (d *downloader) run(ctx context.Context, domains []string) error {
	defer d.stats.log()
	for _, domain := range domains {
		if err := d.download(ctx, domain); err != nil {
			return err
		}
	}
	return nil
}

// runEnumerate performs the enumeration of PMDs for all the given domains.
func (d *downloader) runEnumerate(domains []string) error {
	defer d.stats.log()
	for _, domain := range domains {
		if err := d.enumerate(domain); err != nil {
			return err
		}
	}
	return nil
}
