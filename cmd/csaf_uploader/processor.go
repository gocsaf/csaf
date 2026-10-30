// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022, 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022, 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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
		Proxy:           http.ProxyFromEnvironment,
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

	var createError error
	if resp.StatusCode != http.StatusOK {
		createError = fmt.Errorf("create failed: %s", resp.Status)
	}

	var result struct {
		Message string   `json:"message"`
		Errors  []string `json:"errors"`
	}

	if err := misc.StrictJSONParse(resp.Body, &result); err != nil {
		return err
	}

	if result.Message != "" {
		fmt.Printf("\t%s\n", result.Message)
	}

	writeStrings("Errors:", result.Errors)

	return createError
}

// checkFile runs validations if enabled in the config file
func (p *processor) checkFile(filename string, data []byte) error {
	var err error
	if !p.cfg.NoSchemaCheck {
		var doc any
		if err := misc.StrictJSONParse(bytes.NewReader(data), &doc); err != nil {
			return err
		}
		errs, err := csaf.ValidateCSAF(doc)
		if err != nil {
			return err
		}
		if len(errs) > 0 {
			writeStrings("Errors:", errs)
			return errors.New("local schema check failed")
		}

		eval := util.NewPathEval()
		if err := util.IDMatchesFilename(eval, doc, filepath.Base(filename)); err != nil {
			return err
		}
	}
	return err
}

// createSignature creates a signature if keyring or SigningTool are added in the config
// or if ExternalSigned is set to true in the config.
func (p *processor) createSignature(filename string, data []byte) (string, error) {
	if p.cfg.keyRing != nil {
		sig, err := p.cfg.keyRing.SignDetached(crypto.NewPlainMessage(data))
		if err != nil {
			return "", err
		}
		armored, err := armor.ArmorWithTypeAndCustomHeaders(
			sig.Data, constants.PGPSignatureHeader, "", "")
		if err != nil {
			return "", err
		}
		return armored, nil
	}

	switch {
	case p.cfg.SigningTool != "":
		signature, err := p.signExternally(data)
		if err != nil {
			return "", err
		}
		return signature, nil

	case p.cfg.ExternalSigned:
		signature, err := os.ReadFile(filename + ".asc")
		if err != nil {
			return "", err
		}
		return string(signature), nil
	}
	return "", nil
}

func (p *processor) createMetadata() ([]byte, error) {
	var metadata []byte
	metadata = append(metadata, []byte(p.cfg.TLP)...)
	if p.cfg.keyRing == nil && p.cfg.Passphrase != nil {
		passphrase := []byte(*p.cfg.Passphrase + "\n")
		metadata = append(metadata, passphrase...)
	}
	return metadata, nil
}

// process attemps to upload files to the server via tar stream.
// It prints the response messages.
func (p *processor) process(files []string) error {
	pr, pw := io.Pipe()
	metadata, err := p.createMetadata()
	if err != nil {
		log.Printf("failed to create metadata %v", err)
		return err
	}
	header := &tar.Header{
		Name: "metadata",
		Size: int64(len(metadata)),
	}

	go func() {
		tarWriter := tar.NewWriter(pw)
		defer pw.Close()
		defer tarWriter.Close()
		if err := tarWriter.WriteHeader(header); err != nil {
			log.Printf("failed to write metadata header to tar writer %v", err)
			return
		}
		metadataReader := bytes.NewReader(metadata)

		if _, err := io.Copy(tarWriter, metadataReader); err != nil {
			log.Printf("failed to write metadata to tar writer %v", err)
			return
		}

		for _, filename := range files {
			// Check file name
			if bn := filepath.Base(filename); !util.ConformingFileName(bn) {
				err = fmt.Errorf("%q is not a conforming file name", bn)
				return
			}

			file, err := os.Open(filename)
			if err != nil {
				log.Printf("failed to open file %v", err)
				return
			}
			defer file.Close()

			fileContent, err := os.ReadFile(filename)
			if err != nil {
				log.Printf("could not read file %v", err)
				return
			}

			if err = p.checkFile(filename, fileContent); err != nil {
				log.Printf("failed to check file %v", err)
				return
			}

			fi, err := file.Stat()
			if err != nil {
				log.Printf("failed to read file information %v", err)
				return
			}

			header := &tar.Header{
				Name:    filename,
				Size:    fi.Size(),
				Mode:    int64(fi.Mode()),
				ModTime: fi.ModTime(),
			}
			if err := tarWriter.WriteHeader(header); err != nil {
				log.Printf("failed to write file header to tar writer %v", err)
				return
			}

			if _, err := io.Copy(tarWriter, file); err != nil {
				log.Printf("failed to write file to tar writer %v", err)
				return
			}

			signature, err := p.createSignature(filename, fileContent)
			if err != nil {
				log.Printf("failed to create signature %v", err)
				return
			} else if signature != "" {
				log.Printf("try to write signature")
				header := &tar.Header{
					Name: filename + ".asc",
					Size: int64(len(signature)),
				}

				if err := tarWriter.WriteHeader(header); err != nil {
					log.Printf("failed to write signature header to tar writer %v", err)
					return
				}

				signatureReader := bytes.NewReader([]byte(signature))
				if _, err := io.Copy(tarWriter, signatureReader); err != nil {
					log.Printf("failed to write signature to tar writer %v", err)
					return
				}
			}
		}
	}()

	req, err := http.NewRequest("POST", p.cfg.URL+"/api/bulk_upload/", pr)
	if err != nil {
		log.Printf("failed to create request %v", err)
		return err
	}

	req.Header.Set("X-CSAF-PROVIDER-AUTH", p.cfg.cachedAuth)
	req.Header.Set("Content-Type", "application/x-tar")

	resp, err := p.httpClient().Do(req)
	if err != nil {
		log.Printf("failed to send request %v", err)
		return err
	}

	var uploadErr error
	if resp.StatusCode != http.StatusOK {
		uploadErr := fmt.Errorf("upload failed: %s", resp.Status)
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

	if err := misc.StrictJSONParse(resp.Body, &result); err != nil {
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

func (p *processor) signExternally(data []byte) (string, error) {
	if p.cfg.SigningTool == "" {
		return "", errors.New("no signing tool specified")
	}
	ctx := context.Background()
	if p.cfg.SigningToolTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.cfg.SigningToolTimeout)
		defer cancel()
	}
	var output bytes.Buffer
	cmd := exec.CommandContext(ctx, p.cfg.SigningTool)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = &output
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = 500 * time.Millisecond
	// Create a process group to be killed.
	if p.cfg.SigningToolTimeout > 0 {
		prepareKillingProcessGroup(cmd)
	}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("running signing tool failed: %w", err)
	}
	return output.String(), nil
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

	if err := p.process(args); err != nil {
		log.Print("process returned err")
		return err
	}

	return nil
}
