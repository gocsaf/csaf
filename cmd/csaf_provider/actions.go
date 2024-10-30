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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
) (string, *crypto.Key, error) {

	// Was the signature given via request?
	if c.cfg.UploadSignature {
		sigText := r.FormValue("signature")
		if sigText == "" {
			return "", nil, errors.New("missing signature in request")
		}

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

	if passwd := r.FormValue("passphrase"); !c.cfg.NoPassphrase && passwd != "" {
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
	for _, x := range c.cfg.TLPs {
		if x == t {
			return t, nil
		}
	}
	return "", fmt.Errorf("unsupported TLP type '%s'", t)
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

	// Validate against JSON schema.
	if !c.cfg.NoValidation {
		validationErrors, err := csaf.ValidateCSAF(content)
		if err != nil {
			return nil, err
		}

		if len(validationErrors) > 0 {
			return nil, multiError(validationErrors)
		}
	}

	// Validate against remote validator.
	if c.cfg.RemoteValidator != nil {
		validator, err := c.cfg.RemoteValidator.Open()
		if err != nil {
			return nil, err
		}
		rvr, err := validator.Validate(content)
		if err != nil {
			return nil, err
		}
		if !rvr.Valid {
			return nil, errors.New("does not validate against remote validator")
		}
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

	armored, key, err := c.handleSignature(r, data)
	if err != nil {
		return nil, err
	}

	var warnings []string
	warn := func(msg string) { warnings = append(warnings, msg) }

	if err := doTransaction(
		c.cfg, t,
		func(folder string, pmd *csaf.ProviderMetadata) error {

			// extend the ROLIE feed.
			if err := c.extendROLIE(folder, newCSAF, t, ex); err != nil {
				return err
			}

			// if we have found dynamic categories merge them into
			// the existing once.
			if len(dynamicCategories) > 0 {
				if err := c.mergeCategories(folder, t, dynamicCategories); err != nil {
					return err
				}
			}

			// Create yearly subfolder
			year := strconv.Itoa(ex.InitialReleaseDate.Year())

			subDir := filepath.Join(folder, year)

			// Create folder if it does not exists.
			if _, err := os.Stat(subDir); err != nil {
				if os.IsNotExist(err) {
					if err := os.Mkdir(subDir, 0755); err != nil {
						return err
					}
				} else {
					return err
				}
			}

			fname := filepath.Join(subDir, newCSAF)

			if err := writeHashedFile(fname, newCSAF, data, armored); err != nil {
				return err
			}

			// Only write index.txt and changes.csv if configured.
			if c.cfg.WriteIndices {
				if err := updateIndices(
					folder, filepath.Join(year, newCSAF),
					ex.CurrentReleaseDate,
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

	result := struct {
		Name        string   `json:"name"`
		ReleaseDate string   `json:"release_date"`
		Warnings    []string `json:"warnings,omitempty"`
		Error       error    `json:"-"`
	}{
		Name:        newCSAF,
		ReleaseDate: ex.CurrentReleaseDate.Format(dateFormat),
		Warnings:    warnings,
	}

	return &result, nil
}
