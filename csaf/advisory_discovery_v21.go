// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package csaf

import (
	v21 "github.com/gocsaf/csaf/v3/csaf/v21"
	"github.com/gocsaf/csaf/v3/util"
)

type advisoryDirectory struct {
	url      string
	tlpLabel TLPLabel
}

func extractV21AdvisoryDirectories(document any) ([]advisoryDirectory, error) {
	var provider v21.Provider
	if err := util.ReMarshalJSON(&provider, document); err != nil {
		return nil, err
	}

	var directories []advisoryDirectory
	for i := range provider.Distributions {
		distribution := &provider.Distributions[i]
		if directory := distribution.Directory; directory != nil {
			directories = append(directories, advisoryDirectory{
				url:      string(directory.URL),
				tlpLabel: TLPLabel(directory.TLPLabel),
			})
		}
	}
	return directories, nil
}
