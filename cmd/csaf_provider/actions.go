// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

const dateFormat = time.RFC3339

type Result struct {
	Name        string   `json:"name"`
	ReleaseDate string   `json:"release_date"`
	Warnings    []string `json:"warnings,omitempty"`
	Error       error    `json:"-"`
}

// loadCSAF loads the csaf file from the request, calls the "UploadLimter" function to
// set the upload limit size of the file and the refines
// the filename. It returns the filename, file content in a buffer of bytes
// and an error.
func (c *controller) loadCSAF(r *http.Request) (string, []byte, error) {
	file, handler, err := r.FormFile("csaf")
	if err != nil {
		return "", nil, err
	}
	defer file.Close()

	// We reject everything which is not announced as JSON.
	if handler.Header.Get("Content-Type") != "application/json" {
		return "", nil, errors.New("expected content type 'application/json'")
	}

	if !util.ConformingFileName(handler.Filename) {
		return "", nil, errors.New("given csaf filename is not conforming")
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, c.cfg.uploadLimiter(file)); err != nil {
		return "", nil, err
	}
	return util.CleanFileName(handler.Filename), buf.Bytes(), nil
}

func (c *controller) handleSignature(
	r *http.Request,
	data []byte,
	sigText string,
	passwd string,
) (string, *crypto.Key, error) {

	// Was the signature given via request?
	if c.cfg.UploadSignature {
		pgpSig, err := crypto.NewPGPSignatureFromArmored(sigText)
		if err != nil {
			return "", nil, err
		}

		// Use the public key
		key, err := loadCryptoKeyFromFile(c.cfg.OpenPGPPublicKey)
		if err != nil {
			return "", nil, err
		}

		signRing, err := crypto.NewKeyRing(key)
		if err != nil {
			return "", nil, err
		}

		if err := signRing.VerifyDetached(
			crypto.NewPlainMessage(data),
			pgpSig, crypto.GetUnixTime(),
		); err != nil {
			return "", nil, err
		}

		return sigText, key, nil
	}

	// Sign ourself

	// Use the private key
	key, err := loadCryptoKeyFromFile(c.cfg.OpenPGPPrivateKey)
	if err != nil {
		return "", nil, err
	}

	if !c.cfg.NoPassphrase && passwd != "" {
		if key, err = key.Unlock([]byte(passwd)); err != nil {
			return "", nil, err
		}
	}

	signRing, err := crypto.NewKeyRing(key)
	if err != nil {
		return "", nil, err
	}

	sig, err := signRing.SignDetached(crypto.NewPlainMessage(data))
	if err != nil {
		return "", nil, err
	}

	armored, err := armor.ArmorWithTypeAndCustomHeaders(
		sig.Data, constants.PGPSignatureHeader, "", "")
	return armored, key, err
}

func (c *controller) tlpParam(r *http.Request) (tlp, error) {
	t := tlp(strings.ToLower(r.FormValue("tlp")))
	if slices.Contains(c.cfg.TLPs, t) {
		return t, nil
	}
	return "", fmt.Errorf("unsupported TLP type '%s'", t)
}

// getDynamicCategories returns dynamic categories of a CSAF doc
func (c *controller) getDynamicCategories(content any, pe *util.PathEval) []string {
	var dynamicCategories []string
	if catExprs := c.cfg.DynamicCategories(); len(catExprs) > 0 {
		matcher := util.StringTreeMatcher(&dynamicCategories)

		for _, expr := range catExprs {
			// Compile first to check that the expression is okay.
			if _, err := pe.Compile(expr); err != nil {
				log.Printf("Compiling category expression %q failed: %v\n",
					expr, err)
				continue
			}
			// Ignore errors here as they result from not matching.
			pe.Extract(expr, matcher, true, content)
		}
	}
	return dynamicCategories
}

// doLocalValidation validates a CSAF doc against the JSON schema.
func (c *controller) doLocalValidation(content any) error {
	if !c.cfg.NoValidation {
		validationErrors, err := csaf.ValidateCSAF(content)
		if err != nil {
			return err
		}

		if len(validationErrors) > 0 {
			return multiError(validationErrors)
		}
	}
	return nil
}

// doRemoteValidation validates a CSAF doc against a remote validator.
func (c *controller) doRemoteValidation(content any) error {
	if c.cfg.RemoteValidator != nil {
		validator, err := c.cfg.RemoteValidator.Open()
		if err != nil {
			return err
		}
		rvr, err := validator.Validate(content)
		if err != nil {
			return err
		}
		if !rvr.Valid {
			return errors.New("does not validate against remote validator")
		}
	}
	return nil
}

func (c *controller) runValidations(content any) error {
	if err := c.doLocalValidation(content); err != nil {
		return err
	}

	if err := c.doRemoteValidation(content); err != nil {
		return err
	}
	return nil
}

// createYearlySubfolder creates a subfolder for the given year inside the passed folder.
func (c *controller) createYearlySubfolder(folder string, year string) (string, error) {
	subDir := filepath.Join(folder, year)

	// Create folder if it does not exists.
	if _, err := os.Stat(subDir); err != nil {
		if os.IsNotExist(err) {
			if err := os.Mkdir(subDir, 0755); err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}

	return subDir, nil
}

// create calls the "ensureFolders" functions to create the directories and files.
// It returns a struct by success, otherwise an error.
func (c *controller) create(*http.Request) (any, error) {
	if err := ensureFolders(c.cfg); err != nil {
		return nil, err
	}
	return &struct {
		Message string `json:"message"`
		Error   bool   `json:"-"`
	}{
		Message: "Everything is setup fine now.",
	}, nil
}

func (c *controller) upload(r *http.Request) (any, error) {

	newCSAF, data, err := c.loadCSAF(r)
	if err != nil {
		return nil, err
	}

	var content any
	if err := json.Unmarshal(data, &content); err != nil {
		return nil, err
	}

	if err = c.runValidations(content); err != nil {
		return nil, err
	}

	// Extract informations from the document.
	pe := util.NewPathEval()

	ex, err := csaf.NewAdvisorySummary(pe, content)
	if err != nil {
		return nil, err
	}

	if util.CleanFileName(ex.ID) != newCSAF {
		return nil, fmt.Errorf("ID %q does not match filename %s",
			ex.ID, newCSAF)
	}

	// Check if we have to search for dynamic categories.
	dynamicCategories := c.getDynamicCategories(content, pe)

	t, err := c.tlpParam(r)
	if err != nil {
		return nil, err
	}

	// Extract real TLP from document.
	if t == tlpCSAF {
		if t = tlp(strings.ToLower(ex.TLPLabel)); !t.valid() || t == tlpCSAF {
			return nil, fmt.Errorf(
				"valid TLP label missing in document (found '%s')", t)
		}
	}

	sigText := r.FormValue("signature")
	if sigText == "" {
		return nil, errors.New("missing signature in request")
	}
	passwd := r.FormValue("passphrase")
	armored, key, err := c.handleSignature(r, data, sigText, passwd)
	if err != nil {
		return nil, err
	}

	var warnings []string
	warn := func(msg string) { warnings = append(warnings, msg) }

	if err := doTransaction(
		c.cfg, t,
		func(folder string, pmd *csaf.ProviderMetadata) error {

			// extend the ROLIE feed.
			ts := string(t)
			feedName := "csaf-feed-tlp-" + ts + ".json"

			feed := filepath.Join(folder, feedName)
			rolie, err := c.getROLIE(folder, t, feedName, feed)
			if err != nil {
				return err
			}
			if err := c.extendROLIE(rolie, folder, newCSAF, t, ex); err != nil {
				return err
			}
			c.finalizeROLIE(rolie, feed)

			// if we have found dynamic categories merge them into
			// the existing once.
			if len(dynamicCategories) > 0 {
				if err := c.mergeCategories(folder, t, dynamicCategories); err != nil {
					return err
				}
			}

			year := strconv.Itoa(ex.InitialReleaseDate.Year())

			subDir, err := c.createYearlySubfolder(folder, year)
			if err != nil {
				return err
			}

			fname := filepath.Join(subDir, newCSAF)

			if err := writeHashedFile(fname, newCSAF, data, armored); err != nil {
				return err
			}

			summaries := []SummaryPath{
				SummaryPath{
					Filename: fname,
					Summary:  *ex,
				},
			}

			// Only write index.txt and changes.csv if configured.
			if c.cfg.WriteIndices {
				if err := updateIndices(
					folder, summaries,
				); err != nil {
					return err
				}
			}

			// Take over publisher
			switch {
			case pmd.Publisher == nil:
				warn("Publisher in provider metadata is not initialized. Forgot to configure?")
				if c.cfg.DynamicProviderMetaData {
					warn("Taking publisher from CSAF")
					pmd.Publisher = ex.Publisher
				}
			case !pmd.Publisher.Equals(ex.Publisher):
				warn("Publishers in provider metadata and CSAF do not match.")
			}

			fingerprint := strings.ToUpper(key.GetFingerprint())
			pmd.SetPGP(fingerprint, c.cfg.openPGPPublicURL(fingerprint))

			return nil
		},
	); err != nil {
		return nil, err
	}

	result := Result{
		Name:        newCSAF,
		ReleaseDate: ex.CurrentReleaseDate.Format(dateFormat),
		Warnings:    warnings,
	}

	return &result, nil
}

type UploadMetadata struct {
	Passphrase string `json:"passphrase,omitempty"`
	TLP        string `json:"tlp,omitempty"`
}

// readFile reads the content of a CSAF file and returns the data as byte array and JSON
func (c *controller) readFile(tr *tar.Reader, filename string) ([]byte, any, error) {
	data, err := io.ReadAll(tr)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read content of file %v: %w", filename, err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, c.cfg.uploadLimiter(bytes.NewReader(data))); err != nil {
		return nil, nil, err
	}

	var content any
	if err := json.Unmarshal(data, &content); err != nil {
		return nil, nil, err
	}
	return data, content, nil
}

// readMetadata reads the first file of a tar stream of a bulk request to receive the meta data
// about the uploaded files.
func (c *controller) readMetadata(tr *tar.Reader) (*UploadMetadata, error) {
	_, err := tr.Next()
	if errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("request does not contain metadata: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("extracting metadata failed: %w", err)
	}

	data, err := io.ReadAll(tr)
	if err != nil {
		return nil, fmt.Errorf("cannot read metadata: %w", err)
	}
	var content UploadMetadata
	err = json.Unmarshal(data, &content)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal metadata: %w", err)
	}
	return &content, nil
}

// readSignature reads the signature of a CSAF file from a tar stream
func (c *controller) readSignature(tr *tar.Reader) ([]byte, error) {
	_, err := tr.Next()
	if errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("signature is missing: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("extracting header of signature file failed: %w", err)
	}
	signature, err := io.ReadAll(tr)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// getCleanFilename transforms the filename from the header of a file from a tar stream and
// checks if it is valid.
func (c *controller) getCleanFilename(tr *tar.Reader) (*tar.Header, string, error) {
	// Get header of document file
	header, err := tr.Next()
	if err != nil {
		return nil, "", err
	}

	bn := filepath.Base(header.Name)
	if !util.ConformingFileName(bn) {
		return nil, "", fmt.Errorf("%q is not a conforming file name", bn)
	}

	cleanFilename := util.CleanFileName(bn)
	return header, cleanFilename, nil
}

func (c *controller) getDataFromFile(tr *tar.Reader, pe *util.PathEval) ([]byte, any, *csaf.AdvisorySummary, string, error) {
	header, cleanFilename, err := c.getCleanFilename(tr)
	if err != nil {
		return nil, nil, nil, "", err
	}

	data, content, err := c.readFile(tr, header.Name)
	if err != nil {
		return nil, nil, nil, "", err
	}

	if err = c.runValidations(content); err != nil {
		return nil, nil, nil, "", err
	}

	// Extract informations from the document.
	ex, err := csaf.NewAdvisorySummary(pe, content)
	if err != nil {
		return nil, nil, nil, "", err
	}

	if util.CleanFileName(ex.ID) != cleanFilename {
		return nil, nil, nil, "", fmt.Errorf("ID %q does not match filename %s",
			ex.ID, cleanFilename)
	}
	return data, content, ex, cleanFilename, nil
}

func (c *controller) bulkUpload(r *http.Request) (any, error) {
	// We reject everything which is not announced as tar archive.
	if r.Header.Get("Content-Type") != "application/x-tar" {
		return nil, errors.New("expected content type 'application/x-tar'")
	}

	tarReader := tar.NewReader(r.Body)

	metadata, err := c.readMetadata(tarReader)
	if err != nil {
		return nil, err
	}
	passphrase := metadata.Passphrase
	t := tlp(strings.ToLower(metadata.TLP))

	summaries := []SummaryPath{}
	results := []Result{}
	pe := util.NewPathEval()

	// If the request meta data contains no TLP we Extract it from the first document.
	data, content, ex, cleanFilename, err := c.getDataFromFile(tarReader, pe)
	if errors.Is(err, io.EOF) {
		return nil, errors.New("request contains no files")
	}
	if err != nil {
		return nil, err
	}
	if t == tlpCSAF {
		if t = tlp(strings.ToLower(ex.TLPLabel)); !t.valid() || t == tlpCSAF {
			return nil, fmt.Errorf(
				"valid TLP label missing in first document (found '%s')", t)
		}
	}

	ts := string(t)
	feedName := "csaf-feed-tlp-" + ts + ".json"

	index := 0
	if err := doTransaction(
		c.cfg, t,
		func(folder string, pmd *csaf.ProviderMetadata) error {
			feed := filepath.Join(folder, feedName)
			rolie, err := c.getROLIE(folder, t, feedName, feed)
			if err != nil {
				return err
			}

			for {
				var warnings []string
				warn := func(msg string) { warnings = append(warnings, msg) }

				if index > 0 {
					data, content, ex, cleanFilename, err = c.getDataFromFile(tarReader, pe)
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						return err
					}
				}

				summaries = append(summaries, SummaryPath{
					Filename: cleanFilename,
					Summary:  *ex,
				})

				// Check if we have to search for dynamic categories.
				dynamicCategories := c.getDynamicCategories(content, pe)

				// Extract real TLP from document.
				if index > 0 {
					docTLP := tlp(strings.ToLower(ex.TLPLabel))
					if !docTLP.valid() || t == tlpCSAF {
						return fmt.Errorf(
							"valid TLP label missing in ID %s (found '%s')", ex.ID, t)
					} else if docTLP != t {
						return fmt.Errorf("ID %s does not have correct TLP (wanted: %s, got: %s)", ex.ID, t, docTLP)
					}
				}

				signature, err := c.readSignature(tarReader)
				if err != nil {
					return err
				}

				armored, key, err := c.handleSignature(r, data, string(signature), passphrase)
				if err != nil {
					return err
				}

				// extend the ROLIE feed.
				if err := c.extendROLIE(rolie, folder, cleanFilename, t, ex); err != nil {
					return err
				}

				// If we have found dynamic categories merge them into
				// the existing once.
				if len(dynamicCategories) > 0 {
					if err := c.mergeCategories(folder, t, dynamicCategories); err != nil {
						return err
					}
				}

				// Create yearly subfolder
				year := strconv.Itoa(ex.InitialReleaseDate.Year())

				subDir, err := c.createYearlySubfolder(folder, year)
				if err != nil {
					return err
				}

				fname := filepath.Join(subDir, cleanFilename)

				if err := writeHashedFile(fname, cleanFilename, data, armored); err != nil {
					return err
				}

				if index == 0 {
					fingerprint := strings.ToUpper(key.GetFingerprint())
					pmd.SetPGP(fingerprint, c.cfg.openPGPPublicURL(fingerprint))

					if pmd.Publisher == nil {
						warn("Publisher in provider metadata is not initialized. Forgot to configure?")
						// Take over publisher
						if c.cfg.DynamicProviderMetaData {
							warn("Taking publisher from CSAF")
							pmd.Publisher = ex.Publisher
						}
					}
				} else if !pmd.Publisher.Equals(ex.Publisher) {
					warn("Publishers in provider metadata and CSAF do not match.")
				}

				result := Result{
					Name:        cleanFilename,
					ReleaseDate: ex.CurrentReleaseDate.Format(dateFormat),
					Warnings:    warnings,
				}
				results = append(results, result)
				index++
			}

			c.finalizeROLIE(rolie, feed)

			// Only write index.txt and changes.csv if configured.
			if c.cfg.WriteIndices {
				if err := updateIndices(
					folder, summaries,
				); err != nil {
					return err
				}
			}

			return nil
		}); err != nil {
		return nil, err
	}

	return &results, nil
}
