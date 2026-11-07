// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"path/filepath"
	"strings"
)

// versionTree represents an aggregator serving a specific CSAF version,
// its aggregator.json, provider and publisher mirrors.
type versionTree struct {
	cfg     *config
	folder  string
	path    string
	version string
}

// versionTrees returns list of [versionTree]s for configured CSAF versions.
func (cfg *config) versionTrees() []*versionTree {
	vtrs := make([]*versionTree, 0, len(cfg.CSAFVersions))
	for _, version := range cfg.CSAFVersions {
		vtr := &versionTree{
			cfg:     cfg,
			folder:  cfg.Folder,
			path:    cfg.AggregatorPath,
			version: version,
		}
		if cfg.VersionFolders {
			vtr.path += "/" + versionFolder(version)
			vtr.folder = filepath.Join(cfg.Folder, versionFolder(version))
		}
		vtrs = append(vtrs, vtr)
	}
	return vtrs
}

// versionFolder returns the CSAF version specific folder names i. e. "v2.0" for version "2.0".
func versionFolder(version string) string {
	return "v" + version
}

// dir returns the folder beneath the web root served at the [versionTree] path.
func (vtr *versionTree) dir() string {
	return filepath.Join(vtr.cfg.Web, vtr.path)
}

// aggregatorPath returns the aggregator.json path for a specific [versionTree].
func (vtr *versionTree) aggregatorPath() string {
	return filepath.Join(vtr.dir(), "aggregator.json")
}

// aggregatorURL returns the canonicalURL of the [versionTree]'s aggregator.json.
func (vtr *versionTree) aggregatorURL() string {
	return vtr.url("aggregator.json")
}

// url returns the URL of elements under [versionTree].
func (vtr *versionTree) url(elems ...string) string {
	return vtr.cfg.Domain + vtr.path + "/" + strings.Join(elems, "/")
}

// providers returns list of providers configured with [versionTree]s version.
func (vtr *versionTree) providers() []*provider {
	var pl []*provider
	for _, p := range vtr.cfg.Providers {
		if p.versionConfigured(vtr.version) {
			pl = append(pl, p)
		}
	}
	return pl
}

// prefixVer returns prefix for messages about [versionTree].
// empty if only one version is configured.
func (vtr *versionTree) prefixVer() string {
	if len(vtr.cfg.CSAFVersions) < 2 {
		return ""
	}
	return "CSAF " + vtr.version + ": "
}
