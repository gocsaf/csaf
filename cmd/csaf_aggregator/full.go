// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gocsaf/csaf/v5/csaf"
	"github.com/gocsaf/csaf/v5/csaf/aggregator"
	"github.com/gocsaf/csaf/v5/csaf/types"
	"github.com/gocsaf/csaf/v5/internal/misc"
	"github.com/gocsaf/csaf/v5/util"
)

type fullJob struct {
	provider           *provider
	aggregatorProvider *aggregator.AggregatorCSAFProvidersElem
	vtr                *versionTree
	work               fullWorkFunc
	err                error
}

// setupProviderFull fetches the provider-metadata.json for a specific provider.
func (w *worker) setupProviderFull(ctx context.Context, provider *provider, vtr *versionTree) error {
	w.log.Info("Setting up provider",
		"provider", slog.GroupValue(
			slog.String("name", provider.Name),
			slog.String("domain", provider.Domain),
		))
	w.dir = ""
	w.provider = provider
	w.vtr = vtr

	// Each job needs a separate client.
	w.client = w.processor.cfg.httpClient(provider)

	// We need the provider metadata in all cases.
	if err := w.locateProviderMetadata(ctx, provider.Domain); err != nil {
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
type fullWorkFunc func(*worker, context.Context) (*aggregator.AggregatorCSAFProvidersElem, error)

// fullWork handles the treatment of providers concurrently.
func (w *worker) fullWork(ctx context.Context, wg *sync.WaitGroup, jobs <-chan *fullJob) {
	defer wg.Done()

	for j := range jobs {
		if err := w.setupProviderFull(ctx, j.provider, j.vtr); err != nil {
			j.err = err
			continue
		}
		j.aggregatorProvider, j.err = j.work(w, ctx)
	}
}

// full performs the complete lister/download
func (p *processor) full(ctx context.Context) error {

	if p.cfg.runAsMirror() {
		p.log.Info("Running in aggregator mode")

		// check if we need to setup a remote validator
		if p.cfg.RemoteValidatorOptions != nil {
			validator, err := p.cfg.RemoteValidatorOptions.OpenWithContext()
			if err != nil {
				return err
			}

			// Not sure if we really need it to be serialized.
			p.remoteValidator = csaf.SynchronizedRemoteValidatorWithContext(validator)
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

	pool := misc.NewBufferPool(p.cfg.Workers)

	for i := 1; i <= p.cfg.Workers; i++ {
		wg.Add(1)
		w := newWorker(i, p, pool)

		go w.fullWork(ctx, &wg, queue)
	}

	vtrs := p.cfg.versionTrees()
	jobs := make([][]fullJob, len(vtrs))

	for i, vtr := range vtrs {
		providers := vtr.providers()
		jobs[i] = make([]fullJob, len(providers))
		for j, provider := range providers {
			var work fullWorkFunc
			if provider.runAsMirror(p.cfg) {
				work = (*worker).mirror
			} else {
				work = (*worker).lister
			}
			jobs[i][j] = fullJob{
				provider: provider,
				vtr:      vtr,
				work:     work,
			}
		}
	}
	for i := range jobs {
		for j := range jobs[i] {
			queue <- &jobs[i][j]
		}
	}
	close(queue)

	wg.Wait()

	var errs []error
	for i, vtr := range vtrs {
		if err := p.writeAggregator(vtr, jobs[i]); err != nil {
			errs = append(errs, fmt.Errorf("%s%w", vtr.prefixVer(), err))
		}
	}

	if p.cfg.VersionFolders {
		if err := p.linkAuthoritativeVersion(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// writeAggregator writes an aggregator.json of a [versionTree] from job results.
func (p *processor) writeAggregator(vtr *versionTree, jobs []fullJob) error {

	// Assemble aggregator data structure.
	var providers []aggregator.AggregatorCSAFProvidersElem
	var publishers []aggregator.AggregatorCSAFPublishersElem

	for i := range jobs {
		j := &jobs[i]
		if errors.Is(j.err, errVersionNotServed) {
			p.log.Info("Version tree not served by provider",
				"provider", j.provider.Name,
				"csaf_version", vtr.version)
			continue
		}
		if j.err != nil {
			p.log.Error("Job execution failed",
				slog.Group("job",
					slog.Group("provider"),
					"name", j.provider.Name,
				),
				"csaf_version", vtr.version,
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
				"csaf_version", vtr.version,
			)
			continue
		}

		// "https://" signals a publisher.
		if strings.HasPrefix(j.provider.Domain, "https://") {
			if len(j.aggregatorProvider.Mirrors) == 0 {
				p.log.Error("Publishers can only be listed as mirrors",
					"provider", j.provider.Name,
					"csaf_version", vtr.version)
				continue
			}
			pub := aggregator.AggregatorCSAFPublishersElem{
				Metadata:       j.aggregatorProvider.Metadata,
				Mirrors:        j.aggregatorProvider.Mirrors,
				UpdateInterval: j.provider.updateInterval(p.cfg),
			}
			if slices.ContainsFunc(publishers, func(o aggregator.AggregatorCSAFPublishersElem) bool {
				return reflect.DeepEqual(o, pub)
			}) {
				p.log.Warn("Ignoring duplicate publisher entry",
					"provider", j.provider.Name,
					"csaf_version", vtr.version)
				continue
			}
			publishers = append(publishers, pub)
		} else {
			if slices.ContainsFunc(providers, func(o aggregator.AggregatorCSAFProvidersElem) bool {
				return reflect.DeepEqual(o, *j.aggregatorProvider)
			}) {
				p.log.Warn("Ignoring duplicate provider entry",
					"provider", j.provider.Name,
					"csaf_version", vtr.version)
				continue
			}
			providers = append(providers, *j.aggregatorProvider)
		}
	}

	if len(providers)+len(publishers) == 0 {
		return errors.New("all jobs failed, stopping")
	}

	agg, err := aggregator.NewAggregator(vtr.version)
	if err != nil {
		return err
	}
	agg.Aggregator = p.cfg.aggregatorInfo()
	agg.CanonicalURL = aggregator.AggregatorURLT(vtr.aggregatorURL())
	agg.CSAFProviders = providers
	agg.CSAFPublishers = publishers
	agg.LastUpdated = timestamp(time.Now())
	if from := p.cfg.MaintainedFrom; from != nil {
		ts := timestamp(*from)
		agg.SetMaintainedFrom(&ts)
	}
	if until := p.cfg.MaintainedUntil; until != nil {
		ts := timestamp(*until)
		agg.SetMaintainedUntil(&ts)
	}

	return writeAggregatorFile(vtr.aggregatorPath(), agg)
}

// timestamp returns t as [types.DateTime].
func timestamp(t time.Time) types.DateTime {
	return types.NewDateTime(t.UTC().Truncate(time.Second))
}

// aggregatorInfo returns the configured aggregator section of the aggregator.json.
func (c *config) aggregatorInfo() aggregator.AggregatorAggregator {
	ai := &c.Aggregator
	return aggregator.AggregatorAggregator{
		Category:         *ai.Category,
		Name:             ai.Name,
		Namespace:        ai.Namespace,
		ContactDetails:   ai.ContactDetails,
		IssuingAuthority: ai.IssuingAuthority,
	}
}

// writeAggregatorFile writes the aggregator.json.
func writeAggregatorFile(path string, agg *aggregator.Aggregator) error {
	if err := agg.Check(); err != nil {
		return fmt.Errorf("invalid aggregator.json: %w", err)
	}
	return writeValidatedJSON(path, agg, csaf.ValidateAggregator)
}

// writeValidatedJSON writes v as JSON to path after schema validation.
func writeValidatedJSON(path string, v any, validate func(any) ([]string, error)) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	msgs, err := validate(doc)
	if err != nil {
		return err
	}
	if len(msgs) > 0 {
		return fmt.Errorf("%s does not validate: %s",
			filepath.Base(path), strings.Join(msgs, "; "))
	}

	fname, file, err := util.MakeUniqFile(path + ".tmp")
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		file.Close()
		os.Remove(fname)
		return err
	}

	if err := file.Close(); err != nil {
		os.Remove(fname)
		return err
	}
	if err := os.Rename(fname, path); err != nil {
		os.Remove(fname)
		return err
	}
	return nil
}

// linkAuthoritativeVersion symlinks the aggregator.json of the authoritative
// CSAF version to be available at aggregator_path
func (p *processor) linkAuthoritativeVersion() error {
	link := filepath.Join(p.cfg.Web, p.cfg.AggregatorPath, "aggregator.json")
	target := filepath.Join(versionFolder(p.cfg.AuthoritativeVersion), "aggregator.json")

	if _, err := os.Stat(filepath.Join(filepath.Dir(link), target)); err != nil {
		return fmt.Errorf("cannot link authoritative aggregator.json: %w", err)
	}

	if current, err := os.Readlink(link); err == nil && current == target {
		return nil
	}
	// Switch atomically, e.g. at the roll-over date.
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
