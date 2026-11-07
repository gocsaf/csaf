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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gocsaf/csaf/v5/csaf"
	csafprovider "github.com/gocsaf/csaf/v5/csaf/provider"
	"github.com/gocsaf/csaf/v5/internal/misc"
	"github.com/gocsaf/csaf/v5/util"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

type processor struct {
	// cfg is the global configuration.
	cfg *config

	// remoteValidator is a globally configured remote validator.
	remoteValidator csaf.RemoteValidatorWithContext

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

	client           util.ClientWithContext      // client per provider
	provider         *provider                   // current provider
	metadataProvider any                         // current metadata provider
	metadataModel    *csafprovider.Provider      // typed metadata provider model
	loc              string                      // URL of current provider-metadata.json
	dir              string                      // Directory to store data to.
	summaries        map[string][]summary        // the summaries of the advisories.
	categories       map[string]util.Set[string] // the categories per label.
	log              *slog.Logger                // the structured logger, supplied with the worker number.
	pool             misc.BufferPool
	vtr              *versionTree // [versionTree] of current job
}

func newWorker(num int, processor *processor, pool misc.BufferPool) *worker {
	return &worker{
		num:       num,
		processor: processor,
		expr:      util.NewPathEval(),
		log:       processor.log.With(slog.Int("worker", num)),
		pool:      pool,
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
		filepath.Join(w.vtr.folder, w.provider.Name))
	if err == nil {
		w.dir = dir
	}
	return dir, err
}

// errVersionNotServed is produced by a CSAF version mismatch
// between loaded provider and worker's [versionTree].
var errVersionNotServed = errors.New("CSAF version not served")

func (w *worker) locateProviderMetadata(ctx context.Context, domain string) error {
	loader := csaf.NewProviderMetadataLoader(w.client)
	loader.Version = csaf.SpecVersion(w.vtr.version)
	lpmd := loader.LoadWithContext(ctx, domain)

	if !lpmd.Valid() {
		if slices.ContainsFunc(lpmd.Messages, func(m csaf.ProviderMetadataLoadMessage) bool {
			return m.Type == csaf.VersionMismatch
		}) {
			return fmt.Errorf("%w: %s by %q", errVersionNotServed, w.vtr.version, domain)
		}
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
	w.metadataModel = lpmd.Model
	w.loc = lpmd.URL

	return nil
}

// mirrorURL returns the URL of the given path elements below the
// mirror of the current provider.
func (w *worker) mirrorURL(elems ...string) string {
	return w.vtr.url(w.provider.Name) + "/" + strings.Join(elems, "/")
}

// removeOrphans removes the mirrors of the trees which are not in their
// providers list.
func (p *processor) removeOrphans() error {
	for _, vtr := range p.cfg.versionTrees() {
		keep := util.Set[string]{}
		for _, provider := range vtr.providers() {
			keep.Add(provider.Name)
		}
		if err := p.removeOrphansIn(vtr.dir(), vtr.folder, keep); err != nil {
			return err
		}
	}
	if p.cfg.VersionFolders {
		web := filepath.Join(p.cfg.Web, p.cfg.AggregatorPath)
		return p.removeOrphansIn(web, p.cfg.Folder, util.Set[string]{})
	}
	return nil
}

// removeOrphansIn removes the mirrors in path  that are not in keep.
// Only symlinks to directories are removed, and their targets if
// they are stored in folder.
func (p *processor) removeOrphansIn(path, folder string, keep util.Set[string]) error {
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

	prefix, err := filepath.Abs(folder)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	for _, vtr := range p.cfg.versionTrees() {
		if err := ensureDir(vtr.folder); err != nil {
			return err
		}
		if err := ensureDir(vtr.dir()); err != nil {
			return err
		}
	}

	if err := p.removeOrphans(); err != nil {
		return err
	}

	if p.cfg.Interim {
		return p.interim(ctx)
	}

	return p.full(ctx)
}
