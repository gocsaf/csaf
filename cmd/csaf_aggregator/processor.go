// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

type processor struct {
	cfg *config
}

type job struct {
	provider *provider
	result   *csaf.AggregatorCSAFProvider
	err      error
}

func ensureDir(path string) error {
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		return os.MkdirAll(path, 0750)
	}
	return err
}

func (p *processor) handleProvider(wg *sync.WaitGroup, worker int, jobs <-chan *job) {
	defer wg.Done()

	mirror := p.cfg.Aggregator.Category != nil &&
		*p.cfg.Aggregator.Category == csaf.AggregatorAggregator

	for j := range jobs {
		log.Printf("worker #%d: %s (%s)\n", worker, j.provider.Name, j.provider.Domain)

		if mirror {
			j.err = p.mirror(j.provider)
		}
	}
}

var providerMetadataLocations = [...]string{
	".well-known/csaf",
	"security/data/csaf",
	"advisories/csaf",
	"security/csaf",
}

func (p *processor) locateProviderMetadata(c client, domain string) (interface{}, string, error) {

	var doc interface{}

	download := func(r io.Reader) error {
		if err := json.NewDecoder(r).Decode(&doc); err != nil {
			log.Printf("error: %s\n", err)
			return errNotFound
		}
		return nil
	}

	for _, loc := range providerMetadataLocations {
		url := "https://" + domain + "/" + loc
		if err := downloadJSON(c, url, download); err != nil {
			if err == errNotFound {
				continue
			}
			return nil, "", err
		}
		if doc != nil {
			return doc, url, nil
		}
	}

	// Read from security.txt

	path := "https://" + domain + "/.well-known/security.txt"
	res, err := c.Get(path)
	if err != nil {
		return nil, "", err
	}

	if res.StatusCode != http.StatusOK {
		return nil, "", nil
	}

	loc, err := func() (string, error) {
		defer res.Body.Close()
		urls, err := csaf.ExtractProviderURL(res.Body, false)
		if err != nil {
			return "", err
		}
		if len(urls) == 0 {
			return "", errors.New("No provider-metadata.json found in secturity.txt")
		}
		return urls[0], nil
	}()

	if err != nil {
		return nil, "", err
	}

	if err := downloadJSON(c, loc, download); err != nil {
		return nil, "", err
	}

	return doc, loc, nil
}

// removeOrphans removes the directories that are not in the providers list.
func (p *processor) removeOrphans() error {

	entries, err := func() ([]os.DirEntry, error) {
		dir, err := os.Open(p.cfg.Web)
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		return dir.ReadDir(-1)
	}()

	if err != nil {
		return err
	}

	keep := make(map[string]bool)
	for _, p := range p.cfg.Providers {
		keep[p.Name] = true
	}

	prefix, err := filepath.Abs(p.cfg.Folder)
	if err != nil {
		return err
	}
	prefix, err = filepath.EvalSymlinks(prefix)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if keep[entry.Name()] {
			continue
		}

		fi, err := entry.Info()
		if err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		// only remove the symlinks
		if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
			continue
		}

		d := filepath.Join(p.cfg.Web, entry.Name())
		r, err := filepath.EvalSymlinks(d)
		if err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		fd, err := os.Stat(r)
		if err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		// If its not a directory its not a mirror.
		if !fd.IsDir() {
			continue
		}

		// Remove the link.
		log.Printf("removing link %s -> %s\n", d, r)
		if err := os.Remove(d); err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		// Only remove directories which are in our folder.
		if rel, err := filepath.Rel(prefix, r); err == nil && rel == filepath.Base(r) {
			log.Printf("removing directory %s\n", r)
			if err := os.RemoveAll(r); err != nil {
				log.Printf("error: %v\n", err)
			}
		}
	}

	return nil
}

func (p *processor) process() error {
	if err := ensureDir(p.cfg.Folder); err != nil {
		return err
	}
	web := filepath.Join(p.cfg.Web, ".well-known", "csaf")
	if err := ensureDir(web); err != nil {
		return err
	}

	if err := p.removeOrphans(); err != nil {
		return err
	}

	var wg sync.WaitGroup

	queue := make(chan *job)

	log.Printf("Starting %d workers.\n", p.cfg.Workers)
	for i := 1; i <= p.cfg.Workers; i++ {
		wg.Add(1)
		go p.handleProvider(&wg, i, queue)
	}

	jobs := make([]job, len(p.cfg.Providers))

	for i, p := range p.cfg.Providers {
		jobs[i] = job{provider: p}
		queue <- &jobs[i]
	}
	close(queue)

	wg.Wait()

	// Assemble aggretaor data structure.

	csafProviders := make([]*csaf.AggregatorCSAFProvider, 0, len(jobs))

	for i := range jobs {
		j := &jobs[i]
		if j.err != nil {
			log.Printf("error: '%s' failed: %v\n", j.provider.Name, j.err)
			continue
		}
		if j.result == nil {
			log.Printf("error: '%s' does not produce any result.\n", j.provider.Name)
			continue
		}
		csafProviders = append(csafProviders, j.result)
	}

	version := csaf.AggregatorVersion20
	canonicalURL := csaf.AggregatorURL(p.cfg.Domain + "/.well-known/csaf/aggregator.json")

	agg := csaf.Aggregator{
		Aggregator:    &p.cfg.Aggregator,
		Version:       &version,
		CanonicalURL:  &canonicalURL,
		CSAFProviders: csafProviders,
	}

	dstName := filepath.Join(web, "aggregator.json")

	fname, file, err := util.MakeUniqFile(dstName)
	if err != nil {
		return err
	}

	if _, err := agg.WriteTo(file); err != nil {
		file.Close()
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	return os.Rename(fname, dstName)
}
