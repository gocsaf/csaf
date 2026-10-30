// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// versionTree contains a specific CSAF version's PMD, ROLIE feeds, TLP
// folders, and OpenPGP keys. Providers serving multiple versions keep a
// separate tree for each version.
type versionTree struct {
	cfg     *config
	folder  string
	path    string
	tlps    []tlp
	version string
}

// versionTrees returns list of [versionTree]s for configured CSAF versions.
func (cfg *config) versionTrees() []*versionTree {
	vtrs := make([]*versionTree, 0, len(cfg.CSAFVersions))
	for _, version := range cfg.CSAFVersions {
		vtr := &versionTree{
			cfg:     cfg,
			folder:  cfg.Folder,
			path:    cfg.CSAFPath,
			version: version,
		}
		if cfg.VersionFolders {
			vtr.path += "/" + versionFolder(version)
			vtr.folder = filepath.Join(cfg.Folder, versionFolder(version))
		}
		for _, t := range cfg.TLPs {
			if t.validForVersion(version) {
				vtr.tlps = append(vtr.tlps, t)
			}
		}
		vtrs = append(vtrs, vtr)
	}
	return vtrs
}

// treeForVersion returns the [versionTree] of a given CSAF version.
func (cfg *config) treeForVersion(version string) (*versionTree, error) {
	for _, vtr := range cfg.versionTrees() {
		if vtr.version == version {
			return vtr, nil
		}
	}
	return nil, fmt.Errorf("no version trees for CSAF version %q", version)
}

// versionFolder returns the CSAF version specific folder names i. e. "v2.0" for version "2.0".
func versionFolder(version string) string {
	return "v" + version
}

// dir returns the folder beneath the web root served at the [versionTree] path.
func (vtr *versionTree) dir() string {
	return filepath.Join(vtr.cfg.Web, vtr.path)
}

// feedTLPs returns list of TLPs used by [versionTree].
func (vtr *versionTree) feedTLPs() []tlp {
	tlps := make([]tlp, 0, len(vtr.tlps))
	for _, t := range vtr.tlps {
		if t != tlpCSAF {
			tlps = append(tlps, t)
		}
	}
	return tlps
}

// feedURL returns the URL of the ROLIE feed of a given TLP category in [versionTree].
func (vtr *versionTree) feedURL(t tlp) string {
	return vtr.url(string(t), feedName(t))
}

// hasTLP returns true if given TLP label is used by [versionTree].
func (vtr *versionTree) hasTLP(t tlp) bool {
	return slices.Contains(vtr.tlps, t)
}

// openPGPPublicURL returns the URL of the public OpenPGP key.
func (vtr *versionTree) openPGPPublicURL(fingerprint string) string {
	return vtr.url("openpgp", fingerprint+".asc")
}

// pmdPath returns the PMD path for a specific [versionTree].
func (vtr *versionTree) pmdPath() string {
	return filepath.Join(vtr.dir(), "provider-metadata.json")
}

// pmdURL returns the canonicalURL of the [versionTree]'s PMD.
func (vtr *versionTree) pmdURL() string {
	return vtr.url("provider-metadata.json")
}

// updatesPMD tells if PMD of [versionTree] needs an update
// after upload (dynamic PMD or last_updated per feed in 2.1 PMD)
func (vtr *versionTree) updatesPMD() bool {
	return vtr.cfg.DynamicProviderMetaData || vtr.version == csafVersion21
}

// url returns the URL of elements under [versionTree].
func (vtr *versionTree) url(elems ...string) string {
	return vtr.cfg.CanonicalURLPrefix + vtr.path + "/" + strings.Join(elems, "/")
}
