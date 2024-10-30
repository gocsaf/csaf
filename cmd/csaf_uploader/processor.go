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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/internal/misc"
	"github.com/gocsaf/csaf/v3/util"
)

type processor struct {
	cfg *config
}

// httpClient initializes the http.Client according to the "Insecure" flag
// and the TLS client files for authentication and returns it.
func (p *processor) httpClient() *http.Client {
	var client http.Client
	var tlsConfig tls.Config

	if p.cfg.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if len(p.cfg.clientCerts) != 0 {
		tlsConfig.Certificates = p.cfg.clientCerts
	}

	client.Transport = &http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	return &client
}

// writeStrings prints the passed messages under the specific passed header.
func writeStrings(header string, messages []string) {
	if len(messages) > 0 {
		fmt.Println(header)
		for _, msg := range messages {
			fmt.Printf("\t%s\n", msg)
		}
	}
}

// create sends an request to create the initial files and directories
// on the server. It prints the response messages.
func (p *processor) create() error {
	req, err := http.NewRequest(http.MethodGet, p.cfg.URL+"/api/create", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-CSAF-PROVIDER-AUTH", p.cfg.cachedAuth)

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Create failed: %s\n", resp.Status)
	}

	var result struct {
		Message string   `json:"message"`
		Errors  []string `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if result.Message != "" {
		fmt.Printf("\t%s\n", result.Message)
	}

	writeStrings("Errors:", result.Errors)

	return nil
}

// uploadRequest creates the request for uploading a csaf document by passing the filename.
// According to the flags values the multipart sections of the request are established.
// It returns the created http request.
func (p *processor) uploadRequest(filename string) (*http.Request, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if !p.cfg.NoSchemaCheck {
		var doc any
		if err := json.NewDecoder(bytes.NewReader(data)).Decode(&doc); err != nil {
			return nil, err
		}
		errs, err := csaf.ValidateCSAF(doc)
		if err != nil {
			return nil, err
		}
		if len(errs) > 0 {
			writeStrings("Errors:", errs)
			return nil, errors.New("local schema check failed")
		}

		eval := util.NewPathEval()
		if err := util.IDMatchesFilename(eval, doc, filepath.Base(filename)); err != nil {
			return nil, err
		}
	}

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	// As the csaf_provider only accepts uploads with mime type
	// "application/json" we have to set this.
	part, err := misc.CreateFormFile(
		writer, "csaf", filepath.Base(filename), "application/json")
	if err != nil {
		return nil, err
	}

	if _, err := part.Write(data); err != nil {
		return nil, err
	}

	if err := writer.WriteField("tlp", p.cfg.TLP); err != nil {
		return nil, err
	}

	if p.cfg.keyRing == nil && p.cfg.Passphrase != nil {
		if err := writer.WriteField("passphrase", *p.cfg.Passphrase); err != nil {
			return nil, err
		}
	}

	if p.cfg.keyRing != nil {
		sig, err := p.cfg.keyRing.SignDetached(crypto.NewPlainMessage(data))
		if err != nil {
			return nil, err
		}
		armored, err := armor.ArmorWithTypeAndCustomHeaders(
			sig.Data, constants.PGPSignatureHeader, "", "")
		if err != nil {
			return nil, err
		}
		if err := writer.WriteField("signature", armored); err != nil {
			return nil, err
		}
	}

	if p.cfg.ExternalSigned {
		signature, err := os.ReadFile(filename + ".asc")
		if err != nil {
			return nil, err
		}
		if err := writer.WriteField("signature", string(signature)); err != nil {
			return nil, err
		}
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, p.cfg.URL+"/api/upload", body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-CSAF-PROVIDER-AUTH", p.cfg.cachedAuth)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	return req, nil
}

// process attemps to upload a file to the server.
// It prints the response messages.
func (p *processor) process(filename string) error {

	if bn := filepath.Base(filename); !util.ConformingFileName(bn) {
		return fmt.Errorf("%q is not a conforming file name", bn)
	}

	req, err := p.uploadRequest(filename)
	if err != nil {
		return err
	}

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var uploadErr error
	if resp.StatusCode != http.StatusOK {
		uploadErr = fmt.Errorf("upload failed: %s", resp.Status)
		fmt.Printf("HTTPS %s\n", uploadErr)
	}

	// We expect a JSON answer so all other is not valid.
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		var sb strings.Builder
		if _, err := io.Copy(&sb, resp.Body); err != nil {
			return fmt.Errorf("reading non-JSON reply from server failed: %v", err)
		}
		return fmt.Errorf("non-JSON reply from server: %v", sb.String())
	}

	var result struct {
		Name        string   `json:"name"`
		ReleaseDate string   `json:"release_date"`
		Warnings    []string `json:"warnings"`
		Errors      []string `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if result.Name != "" {
		fmt.Printf("Name: %s\n", result.Name)
	}
	if result.ReleaseDate != "" {
		fmt.Printf("Release date: %s\n", result.ReleaseDate)
	}

	writeStrings("Warnings:", result.Warnings)
	writeStrings("Errors:", result.Errors)

	return uploadErr
}

func (p *processor) run(args []string) error {

	if p.cfg.Action == "create" {
		if err := p.create(); err != nil {
			return err
		}
	}

	if len(args) == 0 {
		log.Println("No CSAF files given.")
	}

	for _, arg := range args {
		if err := p.process(arg); err != nil {
			return fmt.Errorf("processing %q failed: %v", arg, err)
		}
	}

	return nil
}
