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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

type interimJob struct {
	provider *provider
	err      error
}

// statusExpr is used as an expression to check the new status
// of an advisory which was interim before.
const statusExpr = `$.document.tracking.status`

// checkInterims checks the current status of the given
// interim advisories. It returns a slice of advisories
// which are not finished, yet.
func (w *worker) checkInterims(
	tx *lazyTransaction,
	label string,
	interims []interimsEntry,
) ([]interimsEntry, error) {

	var data bytes.Buffer

	labelPath := filepath.Join(tx.Src(), label)

	// advisories which are not interim any longer.
	var notFinalized []interimsEntry

	for _, interim := range interims {

		local := filepath.Join(labelPath, interim.path())
		url := interim.url()

		// Load local SHA256 of the advisory
		localHash, err := util.HashFromFile(local + ".sha256")
		if err != nil {
			return nil, err
		}

		res, err := w.client.Get(url)
		if err != nil {
			return nil, err
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetching %s failed: Status code %d (%s)",
				url, res.StatusCode, res.Status)
		}

		s256 := sha256.New()
		data.Reset()
		hasher := io.MultiWriter(s256, &data)

		var doc any
		if err := func() error {
			defer res.Body.Close()
			tee := io.TeeReader(res.Body, hasher)
			return json.NewDecoder(tee).Decode(&doc)
		}(); err != nil {
			return nil, err
		}

		remoteHash := s256.Sum(nil)

		// If the hashes are equal then we can ignore this advisory.
		if bytes.Equal(localHash, remoteHash) {
			notFinalized = append(notFinalized, interim)
			continue
		}

		errors, err := csaf.ValidateCSAF(doc)
		if err != nil {
			return nil, fmt.Errorf("failed to validate %s: %v", url, err)
		}

		// XXX: Should we return an error here?
		for _, e := range errors {
			w.log.Error("validation error", "url", url, "err", e)
		}

		// We need to write the changed content.

		// This will start the transaction if not already started.
		dst, err := tx.Dst()
		if err != nil {
			return nil, err
		}

		// Overwrite in the cloned folder.
		nlocal := filepath.Join(dst, label, interim.path())

		bytes := data.Bytes()

		if err := os.WriteFile(nlocal, bytes, 0644); err != nil {
			return nil, err
		}

		name := filepath.Base(nlocal)

		if err := util.WriteHashToFile(
			nlocal+".sha512", name, sha512.New(), bytes,
		); err != nil {
			return nil, err
		}
		if err := util.WriteHashSumToFile(
			nlocal+".sha256", name, remoteHash,
		); err != nil {
			return nil, err
		}

		// Download the signature
		sigURL := url + ".asc"
		ascFile := nlocal + ".asc"

		// Download the signature or sign it our self.
		if err := w.downloadSignatureOrSign(sigURL, ascFile, bytes); err != nil {
			return nil, err
		}

		// Check if we can remove this advisory as it is not interim any more.
		var status string
		if err := w.expr.Extract(statusExpr, util.StringMatcher(&status), true, doc); err != nil {
			return nil, err
		}
		if status == "interim" {
			notFinalized = append(notFinalized, interim)
		}
	}

	return notFinalized, nil
}

// setupProviderInterim prepares the worker for a specific provider.
func (w *worker) setupProviderInterim(provider *provider) {
	w.log.Info("Setting up worker", provider.Name, provider.Domain)

	w.dir = ""
	w.provider = provider

	// Each job needs a separate client.
	w.client = w.processor.cfg.httpClient(provider)
}

func (w *worker) interimWork(wg *sync.WaitGroup, jobs <-chan *interimJob) {
	defer wg.Done()
	path := filepath.Join(w.processor.cfg.Web, ".well-known", "csaf-aggregator")

	tooOld := w.processor.cfg.tooOldForInterims()

	for j := range jobs {
		w.setupProviderInterim(j.provider)

		providerPath := filepath.Join(path, j.provider.Name)

		j.err = func() error {
			tx := newLazyTransaction(providerPath, w.processor.cfg.Folder)
			defer tx.rollback()

			// Try all the labels
			for _, label := range []string{
				csaf.TLPLabelUnlabeled,
				csaf.TLPLabelWhite,
				csaf.TLPLabelGreen,
				csaf.TLPLabelAmber,
				csaf.TLPLabelRed,
			} {
				label = strings.ToLower(label)
				labelPath := filepath.Join(providerPath, label)

				interCSV := filepath.Join(labelPath, interimsCSV)
				interims, olds, err := readInterims(interCSV, tooOld)
				if err != nil {
					return err
				}

				// no interims found -> next label.
				if len(interims) == 0 {
					continue
				}

				// Compare locals against remotes.
				notFinalized, err := w.checkInterims(tx, label, interims)
				if err != nil {
					return err
				}

				// Nothing has changed.
				if len(notFinalized) == len(interims) {
					continue
				}

				// Simply append the olds. Maybe we got re-configured with
				// a greater interims interval later.
				notFinalized = append(notFinalized, olds...)

				// We want to write in the transaction folder.
				dst, err := tx.Dst()
				if err != nil {
					return err
				}
				ninterCSV := filepath.Join(dst, label, interimsCSV)
				if err := writeInterims(ninterCSV, notFinalized); err != nil {
					return err
				}
			}
			return tx.commit()
		}()
	}
}

// joinErrors creates an aggregated error of the messages
// of the given errors.
func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	var b strings.Builder
	for i, err := range errs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(err.Error())
	}
	return errors.New(b.String())
}

// interim performs the short interim check/update.
func (p *processor) interim() error {

	if !p.cfg.runAsMirror() {
		return errors.New("interim in lister mode does not work")
	}

	queue := make(chan *interimJob)
	var wg sync.WaitGroup

	p.log.Info("Starting workers...", "num", p.cfg.Workers)
	for i := 1; i <= p.cfg.Workers; i++ {
		wg.Add(1)
		w := newWorker(i, p)
		go w.interimWork(&wg, queue)
	}

	jobs := make([]interimJob, len(p.cfg.Providers))

	for i, p := range p.cfg.Providers {
		jobs[i] = interimJob{provider: p}
		queue <- &jobs[i]
	}
	close(queue)

	wg.Wait()

	var errs []error

	for i := range jobs {
		if err := jobs[i].err; err != nil {
			errs = append(errs, err)
		}
	}

	return joinErrors(errs)
}

type interimsEntry [3]string

// func (ie interimsEntry) date() string { return ie[0] }
func (ie interimsEntry) path() string { return ie[1] }
func (ie interimsEntry) url() string  { return ie[2] }

func writeInterims(interimsCSV string, interims []interimsEntry) error {

	if len(interims) == 0 {
		return os.RemoveAll(interimsCSV)
	}
	// Overwrite old. It's save because we are in a transaction.

	f, err := os.Create(interimsCSV)
	if err != nil {
		return err
	}
	c := csv.NewWriter(f)

	for _, ie := range interims {
		if err := c.Write(ie[:]); err != nil {
			return err
		}
	}

	c.Flush()
	err1 := c.Error()
	err2 := f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// readInterims scans a interims.csv file for matching
// interim advisories. Its sorted with youngest
// first, so we can stop scanning if entries get too old.
// It returns two slices: The advisories that are young enough
// and a slice of the advisories that are too old.
func readInterims(
	interimsCSV string,
	tooOld func(time.Time) bool,
) ([]interimsEntry, []interimsEntry, error) {

	interimsF, err := os.Open(interimsCSV)
	if err != nil {
		// None existing file -> no interims.
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	defer interimsF.Close()

	c := csv.NewReader(interimsF)
	c.FieldsPerRecord = 3

	var files, olds []interimsEntry

	youngEnough := true

	for {
		row, err := c.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}

		if youngEnough {
			t, err := time.Parse(time.RFC3339, row[0])
			if err != nil {
				return nil, nil, err
			}
			if tooOld(t) {
				olds = []interimsEntry{{row[0], row[1], row[2]}}
				youngEnough = false
			} else {
				files = append(files, interimsEntry{row[0], row[1], row[2]})
			}
		} else {
			// These are too old.
			olds = append(olds, interimsEntry{row[0], row[1], row[2]})
		}
	}

	return files, olds, nil
}
