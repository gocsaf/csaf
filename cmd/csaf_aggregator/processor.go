// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

type processor struct {
	// cfg is the global configuration.
	cfg *config

	// remoteValidator is a globally configured remote validator.
	remoteValidator csaf.RemoteValidator

	// log is the structured logger for the whole processor.
	log *slog.Logger
}

type summary struct {
	filename string
	summary  *csaf.AdvisorySummary
	url      string
}

type worker struct {
	num       int
	processor *processor

	expr     *util.PathEval
	signRing *crypto.KeyRing

	client           util.Client                 // client per provider
	provider         *provider                   // current provider
	metadataProvider any                         // current metadata provider
	loc              string                      // URL of current provider-metadata.json
	dir              string                      // Directory to store data to.
	summaries        map[string][]summary        // the summaries of the advisories.
	categories       map[string]util.Set[string] // the categories per label.
	log              *slog.Logger                // the structured logger, supplied with the worker number.
}

func newWorker(num int, processor *processor) *worker {
	return &worker{
		num:       num,
		processor: processor,
		expr:      util.NewPathEval(),
		log:       processor.log.With(slog.Int("worker", num)),
	}
}

func ensureDir(path string) error {
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		return os.MkdirAll(path, 0750)
	}
	return err
}

func (w *worker) createDir() (string, error) {
	if w.dir != "" {
		return w.dir, nil
	}
	dir, err := util.MakeUniqDir(
		filepath.Join(w.processor.cfg.Folder, w.provider.Name))
	if err == nil {
		w.dir = dir
	}
	return dir, err
}

func (w *worker) locateProviderMetadata(domain string) error {

	loader := csaf.NewProviderMetadataLoader(w.client)

	lpmd := loader.Load(domain)

	if !lpmd.Valid() {
		for i := range lpmd.Messages {
			w.log.Error(
				"Loading provider-metadata.json",
				"domain", domain,
				"message", lpmd.Messages[i].Message)
		}
		return fmt.Errorf("no valid provider-metadata.json found for '%s'", domain)
	} else if w.processor.cfg.Verbose {
		for i := range lpmd.Messages {
			w.log.Debug(
				"Loading provider-metadata.json",
				"domain", domain,
				"message", lpmd.Messages[i].Message)
		}
	}

	w.metadataProvider = lpmd.Document
	w.loc = lpmd.URL

	return nil
}

// removeOrphans removes the directories that are not in the providers list.
func (p *processor) removeOrphans() error {

	keep := util.Set[string]{}
	for _, p := range p.cfg.Providers {
		keep.Add(p.Name)
	}

	path := filepath.Join(p.cfg.Web, ".well-known", "csaf-aggregator")

	entries, err := func() ([]os.DirEntry, error) {
		dir, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		return dir.ReadDir(-1)
	}()

	if err != nil {
		return err
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
		if keep.Contains(entry.Name()) {
			continue
		}

		fi, err := entry.Info()
		if err != nil {
			p.log.Error("Could not retrieve file info", "err", err)
			continue
		}

		// only remove the symlinks
		if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
			continue
		}

		d := filepath.Join(path, entry.Name())
		r, err := filepath.EvalSymlinks(d)
		if err != nil {
			p.log.Error("Could not evaluate symlink", "err", err)
			continue
		}

		fd, err := os.Stat(r)
		if err != nil {
			p.log.Error("Could not retrieve file stats", "err", err)
			continue
		}

		// If its not a directory its not a mirror.
		if !fd.IsDir() {
			continue
		}

		// Remove the link.
		p.log.Info("Removing link", "path", fmt.Sprintf("%s -> %s", d, r))
		if err := os.Remove(d); err != nil {
			p.log.Error("Could not remove symlink", "err", err)
			continue
		}

		// Only remove directories which are in our folder.
		if rel, err := filepath.Rel(prefix, r); err == nil &&
			rel == filepath.Base(r) {
			p.log.Info("Remove directory", "path", r)
			if err := os.RemoveAll(r); err != nil {
				p.log.Error("Could not remove directory", "err", err)
			}
		}
	}

	return nil
}

// process is the main driver of the jobs handled by work.
func (p *processor) process() error {
	if err := ensureDir(p.cfg.Folder); err != nil {
		return err
	}
	web := filepath.Join(p.cfg.Web, ".well-known", "csaf-aggregator")
	if err := ensureDir(web); err != nil {
		return err
	}

	if err := p.removeOrphans(); err != nil {
		return err
	}

	if p.cfg.Interim {
		return p.interim()
	}

	return p.full()
}
