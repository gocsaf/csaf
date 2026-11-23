// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/gocsaf/csaf/v3/csaf"
)

type resignResult struct {
	Discovered int      `json:"discovered"`
	Signed     int      `json:"signed"`
	Skipped    int      `json:"skipped"`
	Warnings   []string `json:"warnings,omitempty"`
}

// resign re-signs every advisory referenced by the local provider metadata.
func (c *controller) resign(r *http.Request) (any, error) {
	privateKey, err := c.loadSigningKey(r)
	if err != nil {
		return nil, fmt.Errorf("couldn't load OpenPGP private key: %w", err)
	}
	publicKey, err := loadCryptoKeyFromFile(c.cfg.OpenPGPPublicKey)
	if err != nil {
		return nil, fmt.Errorf("couldn't load OpenPGP public key: %w", err)
	}
	keyRing, err := crypto.NewKeyRing(privateKey)
	if err != nil {
		return nil, err
	}

	wellKnown := filepath.Join(c.cfg.Web, ".well-known", "csaf")
	metaPath := filepath.Join(wellKnown, "provider-metadata.json")
	metaFile, err := os.Open(metaPath)
	if err != nil {
		return nil, fmt.Errorf("couldn't open provider metadata: %w", err)
	}
	pmd, err := csaf.LoadProviderMetadata(metaFile)
	closeErr := metaFile.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}

	result := &resignResult{}
	seen := make(map[string]bool)
	var staged []struct{ target, temp string }
	var fatalErr error
	cleanup := func() {
		for _, s := range staged {
			_ = os.Remove(s.temp)
		}
	}
	// Stage first in case of errors
	stage := func(path, signaturePath string) {
		if fatalErr != nil {
			return
		}
		// Already signed
		if seen[path] {
			return
		}
		seen[path] = true
		// Found one more advisory
		result.Discovered++
		data, err := os.ReadFile(path)
		if err != nil {
			result.Skipped++
			result.Warnings = append(result.Warnings, fmt.Sprintf("could not read %q: %v", path, err))
			return
		}
		sig, err := keyRing.SignDetached(crypto.NewPlainMessage(data))
		if err != nil {
			fatalErr = fmt.Errorf("could not sign %q: %w", path, err)
			cleanup()
			return
		}
		armored, err := armor.ArmorWithTypeAndCustomHeaders(sig.Data, constants.PGPSignatureHeader, "", "")
		if err != nil {
			fatalErr = fmt.Errorf("failed to armor signature for %q: %w", path, err)
			cleanup()
			return
		}
		f, err := os.CreateTemp(filepath.Dir(signaturePath), ".resigning-*.tmp")
		if err != nil {
			fatalErr = fmt.Errorf("failed staging signature for %q: %w", path, err)
			cleanup()
			return
		}
		name := f.Name()
		_, err = f.Write([]byte(armored))
		if err == nil {
			err = f.Sync()
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(name)
			fatalErr = fmt.Errorf("failed staging signature for %q: %w", path, err)
			cleanup()
			return
		}
		staged = append(staged, struct{ target, temp string }{signaturePath, name})
	}
	// Prepare the files filepath
	localForURL := func(providedURL string) (string, error) {
		// Get the url
		u, err := url.Parse(providedURL)
		if err != nil {
			return "", err
		}
		base, err := url.Parse(c.cfg.CanonicalURLPrefix)
		if err != nil {
			return "", err
		}
		// Can't and shouldn't sign external Advisories
		if u.IsAbs() && (u.Host != base.Host || u.Scheme != base.Scheme) {
			return "", fmt.Errorf("can't sign %q: external URL", providedURL)
		}
		u.RawQuery = ""
		// Convert to local URL
		if strings.HasPrefix(u.Path, base.Path) {
			u.Path = strings.TrimPrefix(u.Path, base.Path)
		}
		p := filepath.Join(c.cfg.Web, filepath.FromSlash(strings.TrimPrefix(u.Path, "/")))
		return filepath.Clean(p), nil
	}
	// Add from ROLIE feed
	addROLIEFeed := func(providedURL string) {
		feedPath, err := localForURL(providedURL)
		if err != nil {
			result.Warnings = append(result.Warnings, err.Error())
			return
		}
		f, err := os.Open(feedPath)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("cannot open ROLIE feed %q: %v", feedPath, err))
			return
		}
		feed, err := csaf.LoadROLIEFeed(f)
		_ = f.Close()
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("cannot read ROLIE feed %q: %v", feedPath, err))
			return
		}
		feedURL, _ := url.Parse(providedURL)
		for _, entry := range feed.Feed.Entry {
			var advisoryURL, signatureURL string
			for _, link := range entry.Link {
				if link.Rel == "self" {
					advisoryURL = link.HRef
				}
				// signature may not exist for e.g. currently non-trusted providers
				if link.Rel == "signature" {
					signatureURL = link.HRef
				}
			}
			if advisoryURL != "" {
				linkURL, parseErr := url.Parse(advisoryURL)
				if parseErr != nil {
					result.Warnings = append(result.Warnings, fmt.Sprintf("coudln't parse advisory URL %q: %v", advisoryURL, parseErr))
					continue
				}
				advisory, err := localForURL(feedURL.ResolveReference(linkURL).String())
				if err != nil {
					result.Warnings = append(result.Warnings, err.Error())
					continue
				}

				// signature in case no signatureURL is provided
				signature := advisory + ".asc"
				if signatureURL != "" {
					sigURL, parseErr := url.Parse(signatureURL)
					if parseErr != nil {
						result.Warnings = append(result.Warnings,
							fmt.Sprintf("couldn't parse signature URL %q: %v", signatureURL, parseErr))
						continue
					}

					signature, err = localForURL(feedURL.ResolveReference(sigURL).String())
					if err != nil {
						result.Warnings = append(result.Warnings, err.Error())
						continue
					}
				}
				stage(advisory, signature)
			}
		}
	}
	// add from Directory Listings
	addDirectory := func(providedURL string) {
		dir, err := localForURL(providedURL)
		if err != nil {
			result.Warnings = append(result.Warnings, err.Error())
			return
		}
		// Check index.txt
		if f, err := os.Open(filepath.Join(dir, "index.txt")); err == nil {
			s := bufio.NewScanner(f)
			for s.Scan() {
				name := strings.TrimSpace(s.Text())
				if name != "" {
					advisory := filepath.Join(dir, filepath.FromSlash(name))
					stage(advisory, advisory+".asc")
				}
			}
			if err := s.Err(); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("could not read index.txt: %q: %v", dir, err))
			}
			_ = f.Close()
			return
		} else if !os.IsNotExist(err) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("could not read index.txt: %q: %v", dir, err))
		}
		// Check changes.csv
		if f, err := os.Open(filepath.Join(dir, "changes.csv")); err == nil {
			r := csv.NewReader(f)
			for {
				rec, err := r.Read()
				if err != nil {
					if err != io.EOF {
						result.Warnings = append(result.Warnings, fmt.Sprintf("error while reading changes.csv: %q: %v", dir, err))
					}
					break
				}
				if len(rec) > 0 && rec[0] != "" {
					advisory := filepath.Join(dir, filepath.FromSlash(rec[0]))
					stage(advisory, advisory+".asc")
				}
			}
			_ = f.Close()
		} else if !os.IsNotExist(err) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("could not read changes.csv: %q: %v", dir, err))
		}
	}

	for _, distribution := range pmd.Distributions {
		if distribution.Rolie != nil {
			for _, feed := range distribution.Rolie.Feeds {
				if feed.URL != nil {
					addROLIEFeed(string(*feed.URL))
				}
			}
		} else if distribution.DirectoryURL != "" {
			addDirectory(distribution.DirectoryURL)
		}
	}

	// If signing or staging failed, don't commit. Exit with error instead.
	if fatalErr != nil {
		cleanup()
		return nil, fatalErr
	}
	// Signing and Staging successful, update PMD
	// before applying new signatures in case new signature has not yet been applied
	fingerprint := strings.ToUpper(publicKey.GetFingerprint())
	pmd.SetPGP(fingerprint, c.cfg.openPGPPublicURL(fingerprint))
	// just to be safe in case creating the new PMD fails
	metaTemp, metaFile, err := createTmpPMDBeside(metaPath)
	if err != nil {
		cleanup()
		return nil, err
	}
	if _, err := pmd.WriteTo(metaFile); err != nil {
		_ = metaFile.Close()
		_ = os.Remove(metaTemp)
		cleanup()
		return nil, err
	}
	if err := metaFile.Close(); err != nil {
		_ = os.Remove(metaTemp)
		cleanup()
		return nil, err
	}
	if err := os.Rename(metaTemp, metaPath); err != nil {
		_ = os.Remove(metaTemp)
		return nil, err
	}
	// PMD updated, all advisories found, add the new signatures
	for _, s := range staged {
		if err := os.Rename(s.temp, s.target); err != nil {
			cleanup()
			return nil, fmt.Errorf("writing new signature failed %q: %w", s.target, err)
		}
		result.Signed++
	}
	return result, nil
}

// createTmpPMDBeside creates a temporary PMD next to the given path for staging purposes
func createTmpPMDBeside(path string) (string, *os.File, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".provider-metadata-*.tmp")
	if err != nil {
		return "", nil, err
	}
	return f.Name(), f, nil
}
