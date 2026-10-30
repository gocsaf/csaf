// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf/provider"
	"github.com/gocsaf/csaf/v3/util"
)

func doTransaction(
	vtr *versionTree,
	t tlp,
	fn func(string, *provider.Provider) error,
) error {

	wellknown := vtr.dir()

	pmd, err := vtr.loadPMD()
	if errors.Is(err, os.ErrNotExist) {
		key, err2 := loadCryptoKeyFromFile(vtr.cfg.OpenPGPPublicKey)
		if err2 != nil {
			return err2
		}
		pmd, err = vtr.newProviderMetadata(strings.ToUpper(key.GetFingerprint()), time.Now())
	}
	if err != nil {
		return err
	}

	webTLP := filepath.Join(wellknown, string(t))

	oldDir, err := filepath.EvalSymlinks(webTLP)
	if err != nil {
		return err
	}

	folderTLP := filepath.Join(vtr.folder, string(t))

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

	// Write back provider metadata if its needed.
	if vtr.updatesPMD() {
		pmd.LastUpdated = timestamp(time.Now())
		if err := writePMD(vtr.pmdPath(), pmd); err != nil {
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
