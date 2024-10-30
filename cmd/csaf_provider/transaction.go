// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"os"
	"path/filepath"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

func doTransaction(
	cfg *config,
	t tlp,
	fn func(string, *csaf.ProviderMetadata) error,
) error {

	wellknown := filepath.Join(cfg.Web, ".well-known", "csaf")

	metadata := filepath.Join(wellknown, "provider-metadata.json")

	pmd, err := func() (*csaf.ProviderMetadata, error) {
		f, err := os.Open(metadata)
		if err != nil {
			if os.IsNotExist(err) {
				return csaf.NewProviderMetadataDomain(cfg.CanonicalURLPrefix, cfg.modelTLPs()), nil
			}
			return nil, err
		}
		defer f.Close()
		return csaf.LoadProviderMetadata(f)
	}()

	if err != nil {
		return err
	}

	webTLP := filepath.Join(wellknown, string(t))

	oldDir, err := filepath.EvalSymlinks(webTLP)
	if err != nil {
		return err
	}

	folderTLP := filepath.Join(cfg.Folder, string(t))

	newDir, err := util.MakeUniqDir(folderTLP)
	if err != nil {
		return err
	}

	// Copy old content into new.
	if err := util.DeepCopy(newDir, oldDir); err != nil {
		os.RemoveAll(newDir)
		return err
	}

	// Work with new folder.
	if err := fn(newDir, pmd); err != nil {
		os.RemoveAll(newDir)
		return err
	}

	// Write back provider metadata if its dynamic.
	if cfg.DynamicProviderMetaData {
		newMetaName, newMetaFile, err := util.MakeUniqFile(metadata)
		if err != nil {
			os.RemoveAll(newDir)
			return err
		}

		if _, err := pmd.WriteTo(newMetaFile); err != nil {
			newMetaFile.Close()
			os.Remove(newMetaName)
			os.RemoveAll(newDir)
			return err
		}

		if err := newMetaFile.Close(); err != nil {
			os.Remove(newMetaName)
			os.RemoveAll(newDir)
			return err
		}

		if err := os.Rename(newMetaName, metadata); err != nil {
			os.RemoveAll(newDir)
			return err
		}
	}

	// Switch directories.
	symlink := filepath.Join(newDir, string(t))
	if err := os.Symlink(newDir, symlink); err != nil {
		os.RemoveAll(newDir)
		return err
	}
	if err := os.Rename(symlink, webTLP); err != nil {
		os.RemoveAll(newDir)
		return err
	}

	return os.RemoveAll(oldDir)
}
