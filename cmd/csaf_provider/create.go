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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
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
	if c.VersionFolders {
		if err := checkWellknownPMD(c); err != nil {
			return err
		}
	}

	for _, vtr := range c.versionTrees() {
		for _, create := range []func(*versionTree) error{
			createVersionDir,
			createFeedFolders,
			createService,
			createOpenPGPFolder,
			createProviderMetadata,
		} {
			if err := create(vtr); err != nil {
				return err
			}
		}
	}

	if c.VersionFolders {
		if err := linkAuthoritativeVersion(c); err != nil {
			return err
		}
	}

	// Only write/modify security.txt if configured.
	if c.WriteSecurity {
		if err := setupSecurity(c, filepath.Join(c.Web, ".well-known")); err != nil {
			return err
		}
	}
	return nil
}

// urlsForSecurity returns PMD URLs for security.txt
func urlsForSecurity(c *config) (wanted, stale []string) {
	for _, vtr := range c.versionTrees() {
		if vtr.version == c.AuthoritativeVersion {
			wanted = slices.Insert(wanted, 0, vtr.pmdURL())
		} else {
			wanted = append(wanted, vtr.pmdURL())
		}
	}
	if c.VersionFolders {
		for version := range versionedTLPs {
			if !c.serves(version) {
				stale = append(stale, c.CanonicalURLPrefix+c.CSAFPath+"/"+versionFolder(version)+"/provider-metadata.json")
			}
		}
	}
	return wanted, stale
}

// linkAuthoritativeVersion symlinks the PMD of the authoritative CSAF version
// to be available below csaf_path
func linkAuthoritativeVersion(c *config) error {
	link := wellknownPMD(c)
	target := filepath.Join(versionFolder(c.AuthoritativeVersion), "provider-metadata.json")

	switch current, err := os.Readlink(link); {
	case os.IsNotExist(err):
		return os.Symlink(target, link)
	case err != nil:
		return err
	case current == target:
		return nil
	}
	// atomic switch at roll-over date.
	tmp := link + ".tmp"
	os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// wellknownPMD returns the path to the PMD directly at csaf_path
func wellknownPMD(c *config) string {
	return filepath.Join(c.Web, c.CSAFPath, "provider-metadata.json")
}

// checkWellknownPMD fails when csaf_path contains PMD
// that is not a symlink. This metadata belongs to a tree without
// version folders and must be moved into the appropriate
// version folder (e.g.: "v2.0", "v2.1").
func checkWellknownPMD(c *config) error {
	path := wellknownPMD(c)
	switch st, err := os.Lstat(path); {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return err
	case st.Mode()&os.ModeSymlink == 0:
		return fmt.Errorf("%s not a symlink, move existing CSAF version tree into its respective folder", path)
	}
	return nil
}

// createVersionDir creates a directory of specified [versionTree] if not exist and returns nil.
// An error is returned if the it is not a directory.
func createVersionDir(vtr *versionTree) error {
	dir := vtr.dir()
	st, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(dir, 0755)
		}
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", vtr.path)
	}
	return nil
}

// createService creates the ROLIE service document (if configured).
func createService(vtr *versionTree) error {
	// no service document needed.
	if !vtr.cfg.ServiceDocument {
		return nil
	}

	categories := csaf.ROLIEServiceWorkspaceCollectionCategories{
		Category: []csaf.ROLIEServiceWorkspaceCollectionCategoriesCategory{{
			Scheme: "urn:ietf:params:rolie:category:information-type",
			Term:   "csaf",
		}},
	}

	var collections []csaf.ROLIEServiceWorkspaceCollection

	for _, t := range vtr.feedTLPs() {
		collection := csaf.ROLIEServiceWorkspaceCollection{
			Title:      "CSAF feed (TLP:" + t.label() + ")",
			HRef:       vtr.feedURL(t),
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

	path := filepath.Join(vtr.dir(), "service.json")
	return util.WriteToFile(path, rsd)
}

// createFeedFolders creates the feed folders according to the tlp values
// in the "tlps" config option if they do not already exist.
// No creation for the "csaf" option will be done.
// It creates also symbolic links to feed folders.
func createFeedFolders(vtr *versionTree) error {

	// If we have static configured categories we need to create
	// the category documents.
	categories := vtr.cfg.StaticCategories()

	if err := os.MkdirAll(vtr.folder, 0755); err != nil {
		return err
	}

	for _, t := range vtr.feedTLPs() {
		tlpLink := filepath.Join(vtr.dir(), string(t))
		if _, err := filepath.EvalSymlinks(tlpLink); err != nil {
			if os.IsNotExist(err) {
				tlpFolder := filepath.Join(vtr.folder, string(t))
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
		if len(categories) > 0 {
			if err := mergeCategories(tlpLink, t, categories); err != nil {
				return err
			}
		}
		// Create an empty ROLIE feed document
		if err := createROLIEfeed(vtr, t, tlpLink); err != nil {
			return err
		}
	}
	return nil
}

// createROLIEfeed creates an empty ROLIE feed
func createROLIEfeed(vtr *versionTree, t tlp, folder string) error {
	feed := filepath.Join(folder, feedName(t))

	switch _, err := os.Stat(feed); {
	case err == nil:
		return nil // Keep the entries of the existing feed.
	case !os.IsNotExist(err):
		return err
	}

	links := []csaf.Link{{
		Rel:  "self",
		HRef: vtr.feedURL(t),
	}}
	// If we have a service document we need to link it.
	if vtr.cfg.ServiceDocument {
		links = append(links, csaf.Link{
			Rel:  "service",
			HRef: vtr.url("service.json"),
		})
	}
	rolie := &csaf.ROLIEFeed{
		Feed: csaf.FeedData{
			ID:    "csaf-feed-tlp-" + string(t),
			Title: "CSAF feed (TLP:" + t.label() + ")",
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
func createOpenPGPFolder(vtr *versionTree) error {

	openPGPFolder := filepath.Join(vtr.dir(), "openpgp")

	if _, err := os.Stat(openPGPFolder); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(openPGPFolder, 0755); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	keyData, err := os.ReadFile(vtr.cfg.OpenPGPPublicKey)
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
// it checks if the CSAF entry with the provider-metadata.json
// URLs are already in. Missing ones are added before all other lines.
// No longer served CSAF version entries are removed.
// Otherwise the file is left untouched.
func setupSecurity(c *config, wellknown string) error {
	security := filepath.Join(wellknown, "security.txt")

	wanted, stale := urlsForSecurity(c)

	st, err := os.Stat(security)
	if err != nil {
		if os.IsNotExist(err) {
			f, err := os.Create(security)
			if err != nil {
				return err
			}
			for _, url := range wanted {
				fmt.Fprintf(f, "CSAF: %s\n", url)
			}
			return f.Close()
		}
		return err
	}

	// Load it line wise
	found, lines, removed, err := func() (map[string]bool, []string, bool, error) {
		f, err := os.Open(security)
		if err != nil {
			return nil, nil, false, err
		}
		defer f.Close()
		found := map[string]bool{}
		var lines []string
		removed := false
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if s := strings.TrimLeftFunc(line, unicode.IsSpace); strings.HasPrefix(s, "CSAF:") {
				url := strings.TrimSpace(s[len("CSAF:"):])
				if slices.Contains(stale, url) {
					removed = true
					continue
				}
				found[url] = true
			}
			lines = append(lines, line)
		}
		return found, lines, removed, sc.Err()
	}()
	if err != nil {
		return err
	}

	// Insert our CSAF line at the beginning
	// to get higher priority over possible existing CSAF lines.
	var missing []string
	for _, url := range wanted {
		if !found[url] {
			missing = append(missing, "CSAF: "+url)
		}
	}

	if len(missing) == 0 && !removed {
		return nil
	}

	if len(missing) > 0 {
		lines = append(append(missing, ""), lines...)
	}

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

// createProviderMetadata creates the provider-metadata.json file for [versionTree]
// specifc CSAF version if it does not exist. Keeps already existing one if
// version and validation check out.
func createProviderMetadata(vtr *versionTree) error {
	path := vtr.pmdPath()
	switch _, err := os.Stat(path); {
	case err == nil:
		_, err := vtr.loadPMD()
		return err
	case !os.IsNotExist(err):
		return err
	}

	key, err := loadCryptoKeyFromFile(vtr.cfg.OpenPGPPublicKey)
	if err != nil {
		return fmt.Errorf("cannot load public key: %v", err)
	}

	fingerprint := strings.ToUpper(key.GetFingerprint())

	pmd, err := vtr.newProviderMetadata(fingerprint, time.Now())
	if err != nil {
		return err
	}
	for _, warning := range checkMaintenanceWindow(pmd, time.Now()) {
		log.Println(warning)
	}

	return writePMD(path, pmd)
}
