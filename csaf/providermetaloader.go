// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package csaf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf/provider"
	"github.com/gocsaf/csaf/v3/internal/bare"
	"github.com/gocsaf/csaf/v3/internal/misc"
	"github.com/gocsaf/csaf/v3/util"
)

// ProviderMetadataLoader helps load provider-metadata.json from
// the various locations.
type ProviderMetadataLoader struct {
	client            util.Client
	already           map[string]*LoadedProviderMetadata
	messages          ProviderMetadataLoadMessages
	Version           SpecVersion
	AllowUnmaintained bool
	now               func() time.Time
}

// ProviderMetadataLoadMessageType is the type of the message.
type ProviderMetadataLoadMessageType int

const (
	// JSONDecodingFailed indicates problems with JSON decoding
	JSONDecodingFailed ProviderMetadataLoadMessageType = iota
	// SchemaValidationFailed indicates a general problem with schema validation.
	SchemaValidationFailed
	// SchemaValidationFailedDetail is a failure detail in schema validation.
	SchemaValidationFailedDetail
	// HTTPFailed indicates that loading on HTTP level failed.
	HTTPFailed
	// ExtraProviderMetadataFound indicates an extra PMD found in security.txt.
	ExtraProviderMetadataFound
	// WellknownSecurityMismatch indicates that the PMDs found under wellknown and
	// in the security do not match.
	WellknownSecurityMismatch
	// IgnoreProviderMetadata indicates that an extra PMD was ignored.
	IgnoreProviderMetadata
	// MaintenanceExpired indicates the PMD maintained_until date has passed
	MaintenanceExpired
	// VersionMismatch indicates a mismatch in PMD metadata_version
	VersionMismatch
)

// ProviderMetadataLoadMessage is a message generated while loading
// a provider meta data file.
type ProviderMetadataLoadMessage struct {
	Type    ProviderMetadataLoadMessageType
	Message string
}

// ProviderMetadataLoadMessages is a list of loading messages.
type ProviderMetadataLoadMessages []ProviderMetadataLoadMessage

// LoadedProviderMetadata represents a loaded provider metadata.
type LoadedProviderMetadata struct {
	// URL is location where the document was found.
	URL string
	// Document is the de-serialized JSON document.
	Document any
	// Hash is a SHA256 sum over the document.
	Hash []byte
	// Messages are the error message happened while loading.
	Messages ProviderMetadataLoadMessages
	// Model is CSAF v2.0 or v2.1 typed pmd
	Model *provider.Provider
}

// Add appends a message to the list of loading messages.
func (pmlm *ProviderMetadataLoadMessages) Add(
	typ ProviderMetadataLoadMessageType,
	msg string,
) {
	*pmlm = append(*pmlm, ProviderMetadataLoadMessage{
		Type:    typ,
		Message: msg,
	})
}

// AppendUnique appends unique messages from a second list.
func (pmlm *ProviderMetadataLoadMessages) AppendUnique(other ProviderMetadataLoadMessages) {
	for _, o := range other {
		if !slices.Contains(*pmlm, o) {
			*pmlm = append(*pmlm, o)
		}
	}
}

// Valid returns true if the loaded document is valid.
func (lpm *LoadedProviderMetadata) Valid() bool {
	return lpm != nil && lpm.Document != nil && lpm.Hash != nil && lpm.Model != nil
}

// NewProviderMetadataLoader create a new loader.
func NewProviderMetadataLoader(client util.Client) *ProviderMetadataLoader {
	return &ProviderMetadataLoader{
		client:  client,
		already: map[string]*LoadedProviderMetadata{},
		now:     time.Now,
	}
}

// Enumerate is a wrapper for the EnumerateWithContext function, supplementing
// a required context.Background() as first parameter.
func (pmdl *ProviderMetadataLoader) Enumerate(domain string) []*LoadedProviderMetadata {
	return pmdl.EnumerateWithContext(context.Background(), domain)
}

// EnumerateWithContext lists all PMD files that can be found under the given domain.
// This function is context aware and takes a context.Context as first parameter.
// As specified in CSAF 2.0, it looks for PMDs using the well-known URL and
// the security.txt, and if no PMDs have been found, it also checks the DNS-URL.
func (pmdl *ProviderMetadataLoader) EnumerateWithContext(ctx context.Context, domain string) []*LoadedProviderMetadata {

	// Our array of PMDs to be found
	var resPMDs []*LoadedProviderMetadata

	// Check direct path
	if strings.HasPrefix(domain, "https://") {
		return []*LoadedProviderMetadata{pmdl.loadFromURL(ctx, domain)}
	}

	// First try the well-known path.
	wellknownURL := "https://" + domain + "/.well-known/csaf/provider-metadata.json"

	wellknownResult := pmdl.loadFromURL(ctx, wellknownURL)

	// Validate the candidate and add to the result array
	if wellknownResult.Valid() {
		slog.Debug("Found well known provider-metadata.json")
		resPMDs = append(resPMDs, wellknownResult)
	}

	// Next load the PMDs from security.txt
	secResults := pmdl.loadFromSecurity(ctx, domain)
	slog.Info("Found provider metadata results in security.txt", "num", len(secResults))

	for _, result := range secResults {
		if result.Valid() {
			resPMDs = append(resPMDs, result)
		}
	}

	// According to the spec, only if no PMDs have been found, the should DNS URL be used
	if len(resPMDs) > 0 {
		return resPMDs
	}
	dnsURL := "https://csaf.data.security." + domain
	return []*LoadedProviderMetadata{pmdl.loadFromURL(ctx, dnsURL)}
}

// Load is a wrapper for LoadWithContext, supplementing a
// required context.Background() as first parameter to the LoadWithContext call
func (pmdl *ProviderMetadataLoader) Load(domain string) *LoadedProviderMetadata {
	return pmdl.LoadWithContext(context.Background(), domain)
}

// LoadWithContext loads one valid provider metadata for a given path.
// This function is context aware and takes a context.Context as first parameter.
// If the domain starts with `https://` it only attempts to load
// the data from that URL.
func (pmdl *ProviderMetadataLoader) LoadWithContext(ctx context.Context, domain string) *LoadedProviderMetadata {

	// Check direct path
	if strings.HasPrefix(domain, "https://") {
		return pmdl.loadFromURL(ctx, domain)
	}

	// First try the well-known path.
	wellknownURL := "https://" + domain + "/.well-known/csaf/provider-metadata.json"

	wellknownResult := pmdl.loadFromURL(ctx, wellknownURL)

	// Valid provider metadata under well-known.
	var wellknownGood *LoadedProviderMetadata

	// We have a candidate.
	if wellknownResult.Valid() {
		wellknownGood = wellknownResult
	} else {
		pmdl.messages.AppendUnique(wellknownResult.Messages)
	}

	// Next load the PMDs from security.txt
	secGoods := pmdl.loadFromSecurity(ctx, domain)

	// Mention extra CSAF entries in security.txt.
	ignoreExtras := func() {
		for _, extra := range secGoods[1:] {
			pmdl.messages.Add(
				ExtraProviderMetadataFound,
				fmt.Sprintf("Ignoring extra CSAF entry in security.txt: %s", extra.URL))
		}
	}

	// security.txt contains good entries.
	if len(secGoods) > 0 {
		// we already have a good wellknown, take it.
		if wellknownGood != nil {
			// check if first of security urls is identical to wellknown.
			if bytes.Equal(wellknownGood.Hash, secGoods[0].Hash) {
				ignoreExtras()
			} else {
				// Complaint about not matching.
				pmdl.messages.Add(
					WellknownSecurityMismatch,
					"First entry of security.txt and well-known don't match.")
				// List all the security urls.
				for _, sec := range secGoods {
					pmdl.messages.Add(
						IgnoreProviderMetadata,
						fmt.Sprintf("Ignoring CSAF entry in security.txt: %s", sec.URL))
				}
			}
			// Take the good well-known.
			wellknownGood.Messages = pmdl.messages
			return wellknownGood
		}

		// Don't have well-known. Take first good from security.txt.
		ignoreExtras()
		secGoods[0].Messages = pmdl.messages
		return secGoods[0]
	}

	// If we have a good well-known take it.
	if wellknownGood != nil {
		wellknownGood.Messages = pmdl.messages
		return wellknownGood
	}

	// Last resort: fall back to DNS.
	dnsURL := "https://csaf.data.security." + domain
	dnsURLResult := pmdl.loadFromURL(ctx, dnsURL)
	pmdl.messages.AppendUnique(dnsURLResult.Messages) // keep order of messages consistent (i.e. last occurred message is last element)
	dnsURLResult.Messages = pmdl.messages
	return dnsURLResult
}

// loadFromSecurity loads the PMDs mentioned in the security.txt. Only valid PMDs are returned.
func (pmdl *ProviderMetadataLoader) loadFromSecurity(ctx context.Context, domain string) []*LoadedProviderMetadata {

	// If .well-known fails try legacy location.
	for _, path := range []string{
		"https://" + domain + "/.well-known/security.txt",
		"https://" + domain + "/security.txt",
	} {
		var (
			res *http.Response
			err error
		)
		if cwc, ok := pmdl.client.(util.ClientWithContext); ok {
			res, err = cwc.GetWithContext(ctx, path)
		} else {
			res, err = pmdl.client.Get(path)
		}
		if err != nil {
			pmdl.messages.Add(
				HTTPFailed,
				fmt.Sprintf("Fetching %q failed: %v", path, err))
			continue
		}
		if res.StatusCode != http.StatusOK {
			pmdl.messages.Add(
				HTTPFailed,
				fmt.Sprintf("Fetching %q failed: %s (%d)", path, res.Status, res.StatusCode))
			res.Body.Close()
			continue
		}

		// Extract all potential URLs from CSAF.
		urls, err := func() ([]string, error) {
			defer res.Body.Close()
			return ExtractProviderURL(res.Body, true)
		}()

		if err != nil {
			pmdl.messages.Add(
				HTTPFailed,
				fmt.Sprintf("Loading %q failed: %v", path, err))
			continue
		}

		var loaded []*LoadedProviderMetadata

		// Load the URLs
		for _, url := range urls {
			lpmd := pmdl.loadFromURL(ctx, url)
			// If loading failed note it down.
			if !lpmd.Valid() {
				pmdl.messages.AppendUnique(lpmd.Messages)
				continue
			}
			// Check for duplicates
			if !slices.Contains(loaded, lpmd) {
				loaded = append(loaded, lpmd)
			}
		}

		return loaded
	}
	return nil
}

// loadFromURL loads a provider metadata from a given URL.
func (pmdl *ProviderMetadataLoader) loadFromURL(ctx context.Context, path string) *LoadedProviderMetadata {

	result := LoadedProviderMetadata{URL: path}

	var (
		res *http.Response
		err error
	)
	if cwc, ok := pmdl.client.(util.ClientWithContext); ok {
		res, err = cwc.GetWithContext(ctx, path)
	} else {
		res, err = pmdl.client.Get(path)
	}
	if err != nil {
		result.Messages.Add(
			HTTPFailed,
			fmt.Sprintf("fetching %q failed: %v", path, err))
		return &result
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		result.Messages.Add(
			HTTPFailed,
			fmt.Sprintf("fetching %q failed: %s (%d)", path, res.Status, res.StatusCode))
		return &result
	}

	// TODO: Check for application/json and log it.

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		result.Messages.Add(
			HTTPFailed,
			fmt.Sprintf("reading %q failed: %v", path, err))
		return &result
	}

	var doc any

	if err := misc.StrictJSONParse(bytes.NewReader(raw), &doc); err != nil {
		result.Messages.Add(
			JSONDecodingFailed,
			fmt.Sprintf("JSON decoding failed: %v", err))
		return &result
	}

	// Before checking the err lets check if we had the same
	// document before. If so it will have failed parsing before.

	// Calculate checksum for later comparison.
	sum32 := sha256.Sum256(raw)
	sum := sum32[:]
	key := string(sum)

	// If we already have loaded it return the cached result.
	if r := pmdl.already[key]; r != nil {
		return r
	}

	// write it back as loaded

	switch errors, err := ValidateProviderMetadata(doc); {
	case err != nil:
		result.Messages.Add(
			SchemaValidationFailed,
			fmt.Sprintf("%s: Validating against JSON schema failed: %v", path, err))

	case len(errors) > 0:
		result.Messages = []ProviderMetadataLoadMessage{{
			Type:    SchemaValidationFailed,
			Message: fmt.Sprintf("%s: Validating against JSON schema failed", path),
		}}
		for _, msg := range errors {
			result.Messages.Add(
				SchemaValidationFailedDetail,
				strings.ReplaceAll(msg, `%`, `%%`))
		}
	default:
		pmd, err := decodePMD(raw)
		if err != nil {
			result.Messages.Add(
				JSONDecodingFailed,
				fmt.Sprintf("%s: Decoding pmd model failed: %v", path, err))
			break
		}
		if pmd.MetadataVersion != string(pmdl.Version) && pmdl.Version != "" {
			result.Messages.Add(
				VersionMismatch,
				fmt.Sprintf("%s: requested metadata_version %q, got %q", path, pmdl.Version, pmd.MetadataVersion))
			break
		}
		if err := checkMaintenanceWindow(pmd, path, pmdl.now()); err != nil && !pmdl.AllowUnmaintained {
			result.Messages.Add(MaintenanceExpired, err.Error())
			break
		}
		result.Document = doc
		result.Model = pmd
		result.Hash = sum
	}

	pmdl.already[key] = &result
	return &result
}

// decodePMD decodes raw bytes into a typed pmd model after successful validation.
func decodePMD(raw []byte) (*provider.Provider, error) {
	var bpmd bare.Provider
	if err := json.Unmarshal(raw, &bpmd); err != nil {
		return nil, err
	}
	return provider.FromBare(&bpmd)
}

// maintenanceWarningWindow is the time window for warning about maintaned_until deadline being reached
const maintenanceWarningWindow = 90 * 24 * time.Hour

// checkMaintenanceWindow makes a v2.1 PMD check on the maintenance window defined by maintained_from/maintained_until fields.
func checkMaintenanceWindow(pmd *provider.Provider, path string, now time.Time) error {
	if from, _ := pmd.GetMaintainedFrom(); from != nil {
		t, err := from.Time()
		if err != nil {
			return fmt.Errorf("%s: invalid maintained_from: %w", path, err)
		}
		if now.Before(t) {
			slog.Warn("PMD not maintaned yet", "url", path, "maintained_from", *from)
		}
	}
	if until, _ := pmd.GetMaintainedUntil(); until != nil {
		t, err := until.Time()
		if err != nil {
			return fmt.Errorf("%s: invalid maintained_until: %w", path, err)
		}
		if now.After(t) {
			return fmt.Errorf("%s: mainted_until deadline %s exceeded", path, *until)
		}
		if t.Sub(now) < maintenanceWarningWindow {
			slog.Warn("PMD maintenance window closes in less than 90 days", "url", path, "maintained_until", *until)
		}
	}
	return nil
}
