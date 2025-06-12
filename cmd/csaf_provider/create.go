// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

// ensureFolders initializes the paths and call functions to create
// the directories and files.
func ensureFolders(c *config) error {

	wellknown := filepath.Join(c.Web, ".well-known")
	wellknownCSAF := filepath.Join(wellknown, "csaf")

	for _, create := range []func(*config, string) error{
		createWellknown,
		createFeedFolders,
		createService,
		createOpenPGPFolder,
		createProviderMetadata,
	} {
		if err := create(c, wellknownCSAF); err != nil {
			return err
		}
	}

	// Only write/modify security.txt if configured.
	if c.WriteSecurity {
		if err := setupSecurity(c, wellknown); err != nil {
			return err
		}
	}
	return nil
}

// createWellknown creates ".well-known" directory if not exist and returns nil.
// An error is returned if the it is not a directory.
func createWellknown(_ *config, wellknown string) error {
	st, err := os.Stat(wellknown)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(wellknown, 0755)
		}
		return err
	}
	if !st.IsDir() {
		return errors.New(".well-known/csaf is not a directory")
	}
	return nil
}

// createService creates the ROLIE service document (if configured).
func createService(c *config, wellknownCSAF string) error {
	// no service document needed.
	if !c.ServiceDocument {
		return nil
	}

	categories := csaf.ROLIEServiceWorkspaceCollectionCategories{
		Category: []csaf.ROLIEServiceWorkspaceCollectionCategoriesCategory{{
			Scheme: "urn:ietf:params:rolie:category:information-type",
			Term:   "csaf",
		}},
	}

	var collections []csaf.ROLIEServiceWorkspaceCollection

	for _, t := range c.TLPs {
		if t == tlpCSAF {
			continue
		}
		ts := string(t)
		feedName := "csaf-feed-tlp-" + ts + ".json"
		href := c.CanonicalURLPrefix +
			"/.well-known/csaf/" + ts + "/" + feedName

		collection := csaf.ROLIEServiceWorkspaceCollection{
			Title:      "CSAF feed (TLP:" + strings.ToUpper(ts) + ")",
			HRef:       href,
			Categories: categories,
		}
		collections = append(collections, collection)
	}

	rsd := &csaf.ROLIEServiceDocument{
		Service: csaf.ROLIEService{
			Workspace: []csaf.ROLIEServiceWorkspace{{
				Title:      "CSAF feeds",
				Collection: collections,
			}},
		},
	}

	path := filepath.Join(wellknownCSAF, "service.json")
	return util.WriteToFile(path, rsd)
}

// createFeedFolders creates the feed folders according to the tlp values
// in the "tlps" config option if they do not already exist.
// No creation for the "csaf" option will be done.
// It creates also symbolic links to feed folders.
func createFeedFolders(c *config, wellknown string) error {

	// If we have static configured categories we need to create
	// the category documents.
	var catDoc *csaf.ROLIECategoryDocument

	if categories := c.StaticCategories(); len(categories) > 0 {
		catDoc = csaf.NewROLIECategoryDocument(categories...)
	}

	for _, t := range c.TLPs {
		if t == tlpCSAF {
			continue
		}
		tlpLink := filepath.Join(wellknown, string(t))
		if _, err := filepath.EvalSymlinks(tlpLink); err != nil {
			if os.IsNotExist(err) {
				tlpFolder := filepath.Join(c.Folder, string(t))
				if tlpFolder, err = util.MakeUniqDir(tlpFolder); err != nil {
					return err
				}
				if err = os.Symlink(tlpFolder, tlpLink); err != nil {
					return err
				}
			} else {
				return err
			}
		}
		// Store the category document.
		if catDoc != nil {
			catPath := path.Join(tlpLink, "category-"+string(t)+".json")
			if err := util.WriteToFile(catPath, catDoc); err != nil {
				return err
			}
		}
		// Create an empty ROLIE feed document
		if err := createROLIEfeed(c, t, tlpLink); err != nil {
			return err
		}
	}
	return nil
}

// createROLIEfeed creates an empty ROLIE feed
func createROLIEfeed(c *config, t tlp, folder string) error {
	ts := string(t)
	feedName := "csaf-feed-tlp-" + ts + ".json"

	feed := filepath.Join(folder, feedName)

	feedURL := csaf.JSONURL(
		c.CanonicalURLPrefix +
			"/.well-known/csaf/" + ts + "/" + feedName)

	tlpLabel := csaf.TLPLabel(strings.ToUpper(ts))

	links := []csaf.Link{{
		Rel:  "self",
		HRef: string(feedURL),
	}}
	// If we have a service document we need to link it.
	if c.ServiceDocument {
		links = append(links, csaf.Link{
			Rel:  "service",
			HRef: c.CanonicalURLPrefix + "/.well-known/csaf/service.json",
		})
	}
	rolie := &csaf.ROLIEFeed{
		Feed: csaf.FeedData{
			ID:    "csaf-feed-tlp-" + ts,
			Title: "CSAF feed (TLP:" + string(tlpLabel) + ")",
			Link:  links,
			Category: []csaf.ROLIECategory{{
				Scheme: "urn:ietf:params:rolie:category:information-type",
				Term:   "csaf",
			}},
			Updated: csaf.TimeStamp(time.Now().UTC()),
			Entry:   []*csaf.Entry{},
		},
	}

	return util.WriteToFile(feed, rolie)

}

// createOpenPGPFolder creates an openpgp folder besides
// the provider-metadata.json in the csaf folder.
func createOpenPGPFolder(c *config, wellknown string) error {

	openPGPFolder := filepath.Join(wellknown, "openpgp")

	if _, err := os.Stat(openPGPFolder); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(openPGPFolder, 0755); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	keyData, err := os.ReadFile(c.OpenPGPPublicKey)
	if err != nil {
		return fmt.Errorf("cannot load public OpenPGP key: %v", err)
	}

	key, err := crypto.NewKeyFromArmoredReader(bytes.NewReader(keyData))
	if err != nil {
		return err
	}

	fp := strings.ToUpper(key.GetFingerprint())

	dst := filepath.Join(openPGPFolder, fp+".asc")

	// If we don't have it write it.
	if _, err = os.Stat(dst); err != nil {
		if os.IsNotExist(err) {
			err = os.WriteFile(dst, keyData, 0644)
		}
	}

	return err
}

// setupSecurity creates the "security.txt" file if does not exist
// and writes the CSAF field inside the file. If the file exists
// it checks ig the CSAF entry with the provider-metadata.json
// path is already in. If its not it is added in front of all lines.
// Otherwise the file is left untouched.
func setupSecurity(c *config, wellknown string) error {
	security := filepath.Join(wellknown, "security.txt")

	path := fmt.Sprintf(
		"%s/.well-known/csaf/provider-metadata.json",
		c.CanonicalURLPrefix)

	st, err := os.Stat(security)
	if err != nil {
		if os.IsNotExist(err) {
			f, err := os.Create(security)
			if err != nil {
				return err
			}
			fmt.Fprintf(f, "CSAF: %s\n", path)
			return f.Close()
		}
		return err
	}

	// Load it line wise
	found, lines, err := func() (bool, []string, error) {
		f, err := os.Open(security)
		if err != nil {
			return false, nil, err
		}
		defer f.Close()
		var lines []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if s := strings.TrimLeftFunc(line, unicode.IsSpace); strings.HasPrefix(s, "CSAF:") {
				// Check if we are already in.
				if strings.TrimSpace(s[len("CSAF:"):]) == path {
					return true, nil, nil
				}
			}
			lines = append(lines, line)
		}
		return false, lines, sc.Err()
	}()
	if err != nil {
		return err
	}

	// we are already in the file.
	if found {
		return nil
	}

	// Insert our CSAF line at the beginning
	// to get higher priority over possible existing CSAF lines.
	csafLine := fmt.Sprintf("CSAF: %s", path)
	lines = append([]string{csafLine, ""}, lines...)

	// Write back to second file and switch over afterwards.
	newSecurity, nf, err := util.MakeUniqFile(security + ".tmp")
	if err != nil {
		return err
	}

	for _, line := range lines {
		if _, err := fmt.Fprintln(nf, line); err != nil {
			nf.Close()
			os.RemoveAll(newSecurity)
			return err
		}
	}
	if err := nf.Close(); err != nil {
		os.RemoveAll(newSecurity)
		return err
	}

	// Swap atomically.
	if err := os.Rename(newSecurity, security); err != nil {
		os.RemoveAll(newSecurity)
		return err
	}

	// Re-establish old permissions.
	return os.Chmod(security, st.Mode().Perm())
}

// createProviderMetadata creates the provider-metadata.json file if does not exist.
func createProviderMetadata(c *config, wellknownCSAF string) error {
	path := filepath.Join(wellknownCSAF, "provider-metadata.json")
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	pm := csaf.NewProviderMetadataDomain(c.CanonicalURLPrefix, c.modelTLPs())
	c.ProviderMetaData.apply(pm)

	// We have directory based distributions.
	if c.WriteIndices {
		// Every TLP as a distribution?
		for _, t := range c.TLPs {
			if t != tlpCSAF {
				pm.AddDirectoryDistribution(
					c.CanonicalURLPrefix + "/.well-known/csaf/" + string(t))
			}
		}
	}

	key, err := loadCryptoKeyFromFile(c.OpenPGPPublicKey)
	if err != nil {
		return fmt.Errorf("cannot load public key: %v", err)
	}

	fingerprint := strings.ToUpper(key.GetFingerprint())
	pm.SetPGP(fingerprint, c.openPGPPublicURL(fingerprint))

	return util.WriteToFile(path, pm)
}
