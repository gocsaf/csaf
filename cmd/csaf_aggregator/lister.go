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
	"fmt"

	"github.com/gocsaf/csaf/v5/csaf/aggregator"
)

// mirrorAllowed checks if mirroring is allowed.
func (w *worker) listAllowed() bool {
	return w.metadataModel.ListOnCSAFAggregators
}

func (w *worker) lister(_ context.Context) (*aggregator.AggregatorCSAFProvidersElem, error) {
	// Check if we are allowed to mirror this domain.
	if !w.listAllowed() {
		return nil, fmt.Errorf(
			"no listing of '%s' allowed", w.provider.Name)
	}

	return w.createAggregatorProvider()
}
