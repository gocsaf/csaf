// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/gocsaf/csaf/v5/csaf"
	"github.com/gocsaf/csaf/v5/csaf/aggregator"
	csafprovider "github.com/gocsaf/csaf/v5/csaf/provider"
	"github.com/gocsaf/csaf/v5/internal/misc"
	"github.com/gocsaf/csaf/v5/util"
)

// mirrorAllowed checks if mirroring is allowed.
func (w *worker) mirrorAllowed() bool {
	return w.metadataModel.MirrorOnCSAFAggregators
}

func (w *worker) mirror(ctx context.Context) (*aggregator.AggregatorCSAFProvidersElem, error) {
	result, err := w.mirrorInternal(ctx)
	if err != nil && w.dir != "" {
		// If something goes wrong remove the debris.
		if err := os.RemoveAll(w.dir); err != nil {
			w.log.Error("Could not remove directory", "path", w.dir, "err", err)
		}
	}
	return result, err
}

func (w *worker) mirrorInternal(
	ctx context.Context,
) (*aggregator.AggregatorCSAFProvidersElem, error) {

	// Check if we are allowed to mirror this domain.
	if !w.mirrorAllowed() {
		return nil, fmt.Errorf(
			"no mirroring of '%s' allowed", w.provider.Name)
	}

	// Collecting the summaries of the advisories.
	w.summaries = make(map[string][]summary)

	// Collecting the categories per label.
	w.categories = map[string]util.Set[string]{}

	pmdURL, err := url.Parse(w.loc)
	if err != nil {
		return nil, err
	}

	afp := csaf.NewAdvisoryFileProcessor(
		w.client,
		w.metadataModel,
		pmdURL)

	afp.AgeAccept = w.provider.ageAccept(w.processor.cfg)
	afp.StreamingROLIEParser = w.processor.cfg.StreamingROLIEParser

	if err := afp.ProcessWithContext(ctx, w.mirrorFiles(ctx)); err != nil {
		return nil, err
	}

	if err := w.writeIndices(); err != nil {
		return nil, err
	}

	if err := w.writeProviderMetadata(ctx); err != nil {
		return nil, err
	}

	if err := w.doMirrorTransaction(); err != nil {
		return nil, err
	}

	acp, err := w.createAggregatorProvider()

	if err != nil {
		return nil, err
	}

	// Add us as a mirror.
	acp.Mirrors = aggregator.MirrorsT{
		aggregator.ProviderURLT(w.mirrorURL("provider-metadata.json")),
	}

	return acp, err
}

func (w *worker) labelsFromSummaries() []string {
	labels := make([]string, 0, len(w.summaries))
	for label := range w.summaries {
		labels = append(labels, strings.ToUpper(label))
	}
	slices.Sort(labels)
	return labels
}

// writeProviderMetadata writes a local provider metadata for a mirror.
func (w *worker) writeProviderMetadata(ctx context.Context) error {

	fname := filepath.Join(w.dir, "provider-metadata.json")

	src := w.metadataModel

	pmd, err := csafprovider.NewProviderMetadata(w.vtr.version)
	if err != nil {
		return err
	}
	pmd.CanonicalURL = csafprovider.ProviderURLT(w.mirrorURL("provider-metadata.json"))
	pmd.Publisher = src.Publisher
	pmd.ListOnCSAFAggregators = true
	pmd.MirrorOnCSAFAggregators = true
	pmd.LastUpdated = src.LastUpdated

	if strings.HasPrefix(w.provider.Domain, "https://") {
		pmd.Role = csafprovider.ProviderRoleCSAFPublisher
	} else {
		pmd.Role = csafprovider.ProviderRoleCSAFProvider
	}

	if from, _ := src.MaintainedFrom(); from != nil {
		pmd.SetMaintainedFrom(from)
	}
	if until, _ := src.MaintainedUntil(); until != nil {
		pmd.SetMaintainedUntil(until)
	}

	labels := w.labelsFromSummaries()

	// Register feeds
	now := timestamp(time.Now())
	var feeds []csafprovider.ProviderDistributionsElemRolieFeedsElem
	for _, label := range labels {
		feed, err := pmd.NewFeed()
		if err != nil {
			return err
		}
		lower := strings.ToLower(label)
		summary := "TLP:" + label + " advisories"
		feed.Summary = &summary
		feed.TLPLabel = csafprovider.TLPLabelT(label)
		feed.URL = csafprovider.JsonURLT(w.mirrorURL(lower, feedName(lower)))
		feed.SetLastUpdated(now)
		feeds = append(feeds, feed)
	}
	if len(feeds) > 0 {
		dist, err := pmd.NewDistribution()
		if err != nil {
			return err
		}
		dist.Rolie = &csafprovider.ProviderDistributionsElemRolie{Feeds: feeds}
		pmd.Distributions = append(pmd.Distributions, dist)
	}

	// Fill in directory URLs if needed.
	if w.provider.writeIndices(w.processor.cfg) {
		for _, label := range labels {
			dist, err := pmd.NewDistribution()
			if err != nil {
				return err
			}
			url := w.mirrorURL(strings.ToLower(label))
			switch w.vtr.version {
			case csafVersion20:
				u := csafprovider.URLT(url)
				dist.SetDirectoryURL(&u)
			case csafVersion21:
				dist.SetDirectory(&csafprovider.ProviderDistributionsElemDirectory{
					TLPLabel: csafprovider.TLPLabelT(label),
					URL:      csafprovider.URLT(url),
				})
			}
			pmd.Distributions = append(pmd.Distributions, dist)
		}
	}

	// We are mirroring the remote public keys, too.
	pmd.PublicOpenpgpKeys = slices.Clone(src.PublicOpenpgpKeys)
	if err := w.mirrorPGPKeys(ctx, pmd); err != nil {
		return err
	}

	if err := pmd.Check(); err != nil {
		return fmt.Errorf("invalid provider-metadata.json of mirror: %w", err)
	}
	return writeValidatedJSON(fname, pmd, csaf.ValidateProviderMetadata)

}

// feedName returns the file name of the ROLIE feed of a TLP label
// in lower case.
func feedName(label string) string {
	return "csaf-feed-tlp-" + label + ".json"
}

// mirrorPGPKeys creates a local openpgp folder and downloads the referenced
// OpenPGP keys into it. The own key is also inserted.
func (w *worker) mirrorPGPKeys(ctx context.Context, pm *csafprovider.Provider) error {
	openPGPFolder := filepath.Join(w.dir, "openpgp")
	if err := os.MkdirAll(openPGPFolder, 0755); err != nil {
		return err
	}

	localKeyURL := func(fingerprint string) string {
		return w.mirrorURL("openpgp", fingerprint+".asc")
	}

	for i := range pm.PublicOpenpgpKeys {
		pgpKey := &pm.PublicOpenpgpKeys[i]
		if pgpKey.URL == "" {
			w.log.Warn("Ignoring PGP key without URL", "fingerprint", pgpKey.Fingerprint)
			continue
		}
		if pgpKey.Fingerprint == nil {
			w.log.Warn("Ignoring PGP key without fingerprint", "url", pgpKey.URL)
			continue
		}
		if _, err := hex.DecodeString(*pgpKey.Fingerprint); err != nil {
			w.log.Warn("Ignoring PGP key with invalid fingerprint", "url", pgpKey.URL)
			continue
		}

		// Fetch remote key.
		res, err := w.client.GetWithContext(ctx, string(pgpKey.URL))
		if err != nil {
			os.RemoveAll(openPGPFolder)
			return err
		}

		if res.StatusCode != http.StatusOK {
			os.RemoveAll(openPGPFolder)
			res.Body.Close()
			return fmt.Errorf("cannot fetch PGP key %s: %s (%d)",
				pgpKey.URL, res.Status, res.StatusCode)
		}

		fingerprint := strings.ToUpper(*pgpKey.Fingerprint)

		localFile := filepath.Join(openPGPFolder, fingerprint+".asc")

		// Download the remote key into our new folder.
		if err := func() error {
			defer res.Body.Close()
			out, err := os.Create(localFile)
			if err != nil {
				return err
			}
			_, err1 := io.Copy(out, res.Body)
			err2 := out.Close()
			if err1 != nil {
				return err1
			}
			return err2
		}(); err != nil {
			os.RemoveAll(openPGPFolder)
			return err
		}

		// replace the URL
		pgpKey.URL = csafprovider.URLT(localKeyURL(fingerprint))
	}

	// If we have public key configured copy it into the new folder

	if w.processor.cfg.OpenPGPPublicKey == "" {
		return nil
	}

	// Load the key for the fingerprint.
	data, err := os.ReadFile(w.processor.cfg.OpenPGPPublicKey)
	if err != nil {
		os.RemoveAll(openPGPFolder)
		return err
	}

	key, err := crypto.NewKeyFromArmoredReader(bytes.NewReader(data))
	if err != nil {
		os.RemoveAll(openPGPFolder)
		return err
	}

	fingerprint := strings.ToUpper(key.GetFingerprint())

	localFile := filepath.Join(openPGPFolder, fingerprint+".asc")

	// Write copy back into new folder.
	if err := os.WriteFile(localFile, data, 0644); err != nil {
		os.RemoveAll(openPGPFolder)
		return err
	}

	// Add to the URLs.
	pm.SetPGP(fingerprint, localKeyURL(fingerprint))

	return nil
}

// createAggregatorProvider fills the "metadata" section in the "csaf_providers" of
// the aggregator document.
func (w *worker) createAggregatorProvider() (*aggregator.AggregatorCSAFProvidersElem, error) {
	pmd := w.metadataModel

	pub, err := aggregator.PublisherFromProvider(&pmd.Publisher)
	if err != nil {
		return nil, err
	}
	role := aggregator.RoleT(pmd.Role)

	return &aggregator.AggregatorCSAFProvidersElem{
		Metadata: aggregator.AggregatorCSAFProvidersElemMetadata{
			LastUpdated: pmd.LastUpdated,
			Publisher:   pub,
			Role:        &role,
			URL:         aggregator.ProviderURLT(pmd.CanonicalURL),
		},
	}, nil
}

// doMirrorTransaction performs an atomic directory swap.
func (w *worker) doMirrorTransaction() error {

	webTarget := filepath.Join(w.vtr.dir(), w.provider.Name)

	var oldWeb string

	// Resolve old to be removed later
	if _, err := os.Stat(webTarget); err != nil {
		if !os.IsNotExist(err) {
			os.RemoveAll(w.dir)
			return err
		}
	} else {
		if oldWeb, err = filepath.EvalSymlinks(webTarget); err != nil {
			os.RemoveAll(w.dir)
			return err
		}
	}

	// Check if there is a sysmlink already.
	target := filepath.Join(w.vtr.folder, w.provider.Name)
	w.log.Debug("Checking for path existance", "path", target)

	exists, err := util.PathExists(target)
	if err != nil {
		os.RemoveAll(w.dir)
		return err
	}

	if exists {
		if err := os.RemoveAll(target); err != nil {
			os.RemoveAll(w.dir)
			return err
		}
	}

	w.log.Debug("Creating sym link", "from", w.dir, "to", target)

	// Create a new symlink
	if err := os.Symlink(w.dir, target); err != nil {
		os.RemoveAll(w.dir)
		return err
	}

	// Move the symlink
	w.log.Debug("Moving sym link", "from", target, "to", webTarget)
	if err := os.Rename(target, webTarget); err != nil {
		os.RemoveAll(w.dir)
		return err
	}

	// Finally remove the old folder.
	if oldWeb != "" {
		return os.RemoveAll(oldWeb)
	}
	return nil
}

// downloadSignature downloads an OpenPGP signature from a given url.
func (w *worker) downloadSignature(ctx context.Context, path string) (string, error) {
	res, err := w.client.GetWithContext(ctx, path)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return "", errNotFound
	}
	data, err := func() ([]byte, error) {
		defer res.Body.Close()
		return io.ReadAll(res.Body)
	}()
	if err != nil {
		return "", err
	}
	result := string(data)
	if _, err := crypto.NewPGPMessageFromArmored(result); err != nil {
		return "", err
	}
	return result, nil
}

// sign signs the given data with the configured key.
func (w *worker) sign(data []byte) (string, error) {
	if w.signRing == nil {
		key, err := w.processor.cfg.privateOpenPGPKey()
		if err != nil {
			return "", err
		}
		if key == nil {
			return "", nil
		}
		if pp := w.processor.cfg.Passphrase; pp != nil {
			if key, err = key.Unlock([]byte(*pp)); err != nil {
				return "", err
			}
		}
		if w.signRing, err = crypto.NewKeyRing(key); err != nil {
			return "", err
		}
	}
	sig, err := w.signRing.SignDetached(crypto.NewPlainMessage(data))
	if err != nil {
		return "", err
	}
	return armor.ArmorWithTypeAndCustomHeaders(
		sig.Data, constants.PGPSignatureHeader, "", "")
}

func (w *worker) extractCategories(label string, advisory any) error {

	// use provider or global categories
	var categories []string
	if w.provider.Categories != nil {
		categories = *w.provider.Categories
	} else if w.processor.cfg.Categories != nil {
		categories = *w.processor.cfg.Categories
	}

	// Nothing to do.
	if len(categories) == 0 {
		return nil
	}

	cats := w.categories[label]
	if cats == nil {
		cats = util.Set[string]{}
		w.categories[label] = cats
	}

	const exprPrefix = "expr:"

	var dynamic []string
	matcher := util.StringTreeMatcher(&dynamic)

	for _, cat := range categories {
		if strings.HasPrefix(cat, exprPrefix) {
			expr := cat[len(exprPrefix):]
			// Compile first to check that the expression is okay.
			if _, err := w.expr.Compile(expr); err != nil {
				slog.Error("Compiling category expression failed",
					"expr", expr,
					"err", err)
				continue
			}
			// Ignore errors here as they result from not matching.
			w.expr.Extract(expr, matcher, true, advisory)
		} else { // Normal
			cats.Add(cat)
		}
	}

	// Add dynamic categories.
	for _, cat := range dynamic {
		cats.Add(cat)
	}

	return nil
}

func (w *worker) mirrorFiles(ctx context.Context) func(csaf.TLPLabel, []csaf.AdvisoryFile) error {
	return func(tlpLabel csaf.TLPLabel, files []csaf.AdvisoryFile) error {
		return w.mirrorFilesWithContext(ctx, tlpLabel, files)
	}
}

func (w *worker) mirrorFilesWithContext(
	ctx context.Context,
	tlpLabel csaf.TLPLabel,
	files []csaf.AdvisoryFile,
) error {
	label := strings.ToLower(string(tlpLabel))

	summaries := w.summaries[label]

	dir, err := w.createDir()
	if err != nil {
		return err
	}

	yearDirs := make(map[int]string)

	mirrorFile := func(file csaf.AdvisoryFile) error {

		u, err := url.Parse(file.URL())
		if err != nil {
			w.log.Error("Could not parse advisory file URL", "err", err)
			return nil
		}

		// Should we ignore this advisory?
		if w.provider.ignoreURL(file.URL(), w.processor.cfg) {
			if w.processor.cfg.Verbose {
				w.log.Info("Ignoring advisory", slog.Group("provider", "name", w.provider.Name), "file", file)
			}
			return nil
		}

		// Ignore not conforming filenames.
		filename := filepath.Base(u.Path)
		if !util.ConformingFileName(filename) {
			w.log.Warn("Ignoring advisory because of non-conforming filename", "filename", filename)
			return nil
		}

		var advisory any

		s256 := sha256.New()
		s512 := sha512.New()
		content := w.pool.Get()
		defer w.pool.Put(content)
		hasher := io.MultiWriter(s256, s512, content)

		download := func(r io.Reader) error {
			tee := io.TeeReader(r, hasher)
			return misc.StrictJSONParse(tee, &advisory)
		}

		if err := downloadJSON(ctx, w.client, file.URL(), download); err != nil {
			w.log.Error("Error while downloading JSON", "err", err)
			return nil
		}

		// Check against CSAF schema.
		errors, err := csaf.ValidateCSAF(advisory)
		if err != nil {
			w.log.Error("Error while validating CSAF schema", "err", err)
			return nil
		}
		if len(errors) > 0 {
			w.log.Error("CSAF file has validation errors", "num.errors", len(errors), "file", file)
			return nil
		}

		// Check against remote validator.
		// XXX: TODO: disable remote validation with CSAF version 2.1, while it's not yet possible.
		if rmv := w.processor.remoteValidator; rmv != nil && w.vtr.version == csafVersion20 {
			rvr, err := rmv.ValidateWithContext(ctx, advisory)
			if err != nil {
				w.log.Error("Calling remote validator failed", "err", err)
				return nil
			}
			if !rvr.Valid {
				w.log.Error("CSAF file does not validate remotely", "file", file.URL())
				return nil
			}
		}

		sum, err := csaf.NewAdvisorySummary(w.expr, advisory)
		if err != nil {
			w.log.Error("Error while creating new advisory", "file", file, "err", err)
			return nil
		}

		if sum.CSAFVersion != w.vtr.version {
			w.log.Error("Ignoring advisory of other CSAF version",
				"file", file.URL(),
				"csaf_version", sum.CSAFVersion,
				"metadata_version", w.vtr.version)
			return nil
		}

		if util.CleanFileName(sum.ID) != filename {
			w.log.Error("ID mismatch", "id", sum.ID, "filename", filename)
		}

		if err := w.extractCategories(label, advisory); err != nil {
			w.log.Error("Could not extract categories", "file", file, "err", err)
			return nil
		}

		summaries = append(summaries, summary{
			filename: filename,
			summary:  sum,
			url:      file.URL(),
		})

		year := sum.InitialReleaseDate.Year()

		yearDir := yearDirs[year]
		if yearDir == "" {
			yearDir = filepath.Join(dir, label, strconv.Itoa(year))
			if err := os.MkdirAll(yearDir, 0755); err != nil {
				return err
			}
			yearDirs[year] = yearDir
		}

		fname := filepath.Join(yearDir, filename)
		data := content.Bytes()
		if err := writeFileHashes(
			fname, filename,
			data, s256.Sum(nil), s512.Sum(nil),
		); err != nil {
			return err
		}

		// Try to fetch signature file.
		sigURL := file.SignURL()
		ascFile := fname + ".asc"
		return w.downloadSignatureOrSign(ctx, sigURL, ascFile, data)
	}

	for _, file := range files {
		if err := mirrorFile(file); err != nil {
			return err
		}
	}
	w.summaries[label] = summaries

	return nil
}

// downloadSignatureOrSign first tries to download a signature.
// If this fails it creates a signature itself with the configured key.
func (w *worker) downloadSignatureOrSign(ctx context.Context, url, fname string, data []byte) error {
	sig, err := w.downloadSignature(ctx, url)
	if err != nil {
		if err != errNotFound {
			w.log.Error("Could not find signature URL", "url", url, "err", err)
		}
		// Sign it our self.
		if sig, err = w.sign(data); err != nil {
			return err
		}
	}

	if sig != "" {
		err = os.WriteFile(fname, []byte(sig), 0644)
	}
	return err
}
