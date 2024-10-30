// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

type fullJob struct {
	provider           *provider
	aggregatorProvider *csaf.AggregatorCSAFProvider
	work               fullWorkFunc
	err                error
}

// setupProviderFull fetches the provider-metadata.json for a specific provider.
func (w *worker) setupProviderFull(provider *provider) error {
	w.log.Info("Setting up provider",
		"provider", slog.GroupValue(
			slog.String("name", provider.Name),
			slog.String("domain", provider.Domain),
		))
	w.dir = ""
	w.provider = provider

	// Each job needs a separate client.
	w.client = w.processor.cfg.httpClient(provider)

	// We need the provider metadata in all cases.
	if err := w.locateProviderMetadata(provider.Domain); err != nil {
		return err
	}

	// Validate the provider metadata.
	errors, err := csaf.ValidateProviderMetadata(w.metadataProvider)
	if err != nil {
		return err
	}
	if len(errors) > 0 {
		return fmt.Errorf(
			"provider-metadata.json has %d validation issues", len(errors))
	}

	w.log.Info("Using provider-metadata", "url", w.loc)
	return nil
}

// fullWorkFunc implements the actual work (mirror/list).
type fullWorkFunc func(*worker) (*csaf.AggregatorCSAFProvider, error)

// fullWork handles the treatment of providers concurrently.
func (w *worker) fullWork(wg *sync.WaitGroup, jobs <-chan *fullJob) {
	defer wg.Done()

	for j := range jobs {
		if err := w.setupProviderFull(j.provider); err != nil {
			j.err = err
			continue
		}
		j.aggregatorProvider, j.err = j.work(w)
	}
}

// full performs the complete lister/download
func (p *processor) full() error {

	if p.cfg.runAsMirror() {
		p.log.Info("Running in aggregator mode")

		// check if we need to setup a remote validator
		if p.cfg.RemoteValidatorOptions != nil {
			validator, err := p.cfg.RemoteValidatorOptions.Open()
			if err != nil {
				return err
			}

			// Not sure if we really need it to be serialized.
			p.remoteValidator = csaf.SynchronizedRemoteValidator(validator)
			defer func() {
				p.remoteValidator.Close()
				p.remoteValidator = nil
			}()
		}
	} else {
		p.log.Info("Running in lister mode")
	}

	queue := make(chan *fullJob)
	var wg sync.WaitGroup

	p.log.Info("Starting workers...", "num", p.cfg.Workers)

	for i := 1; i <= p.cfg.Workers; i++ {
		wg.Add(1)
		w := newWorker(i, p)

		go w.fullWork(&wg, queue)
	}

	jobs := make([]fullJob, len(p.cfg.Providers))

	for i, provider := range p.cfg.Providers {
		var work fullWorkFunc
		if provider.runAsMirror(p.cfg) {
			work = (*worker).mirror
		} else {
			work = (*worker).lister
		}
		jobs[i] = fullJob{
			provider: provider,
			work:     work,
		}
		queue <- &jobs[i]
	}
	close(queue)

	wg.Wait()

	// Assemble aggregator data structure.
	var providers []*csaf.AggregatorCSAFProvider
	var publishers []*csaf.AggregatorCSAFPublisher

	for i := range jobs {
		j := &jobs[i]
		if j.err != nil {
			p.log.Error("Job execution failed",
				slog.Group("job",
					slog.Group("provider"),
					"name", j.provider.Name,
				),
				"err", j.err,
			)
			continue
		}
		if j.aggregatorProvider == nil {
			p.log.Error("Job did not produce any result",
				slog.Group("job",
					slog.Group("provider"),
					"name", j.provider.Name,
				),
			)
			continue
		}

		// "https://" signals a publisher.
		if strings.HasPrefix(j.provider.Domain, "https://") {
			pub := &csaf.AggregatorCSAFPublisher{
				Metadata:       j.aggregatorProvider.Metadata,
				Mirrors:        j.aggregatorProvider.Mirrors,
				UpdateInterval: j.provider.updateInterval(p.cfg),
			}
			publishers = append(publishers, pub)
		} else {
			providers = append(providers, j.aggregatorProvider)
		}
	}

	if len(providers)+len(publishers) == 0 {
		return errors.New("all jobs failed, stopping")
	}

	version := csaf.AggregatorVersion20
	canonicalURL := csaf.AggregatorURL(
		p.cfg.Domain + "/.well-known/csaf-aggregator/aggregator.json")

	lastUpdated := csaf.TimeStamp(time.Now().UTC())

	agg := csaf.Aggregator{
		Aggregator:     &p.cfg.Aggregator,
		Version:        &version,
		CanonicalURL:   &canonicalURL,
		CSAFProviders:  providers,
		CSAFPublishers: publishers,
		LastUpdated:    &lastUpdated,
	}

	web := filepath.Join(p.cfg.Web, ".well-known", "csaf-aggregator")

	dstName := filepath.Join(web, "aggregator.json")

	fname, file, err := util.MakeUniqFile(dstName + ".tmp")
	if err != nil {
		return err
	}

	if _, err := agg.WriteTo(file); err != nil {
		file.Close()
		os.RemoveAll(fname)
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	return os.Rename(fname, dstName)
}
