// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package csaf

import v21 "github.com/gocsaf/csaf/v3/csaf/v21"

// ValidateCSAF validates doc against the CSAF 2.1 JSON schema.
func ValidateCSAF(doc any) ([]string, error) {
	return v21.ValidateCSAF(doc)
}

// ValidateProviderMetadata validates doc against the provider metadata 2.1 JSON schema.
func ValidateProviderMetadata(doc any) ([]string, error) {
	return v21.ValidateProviderMetadata(doc)
}

// ValidateAggregator validates doc against the aggregator metadata 2.1 JSON schema.
func ValidateAggregator(doc any) ([]string, error) {
	return v21.ValidateAggregator(doc)
}

// ValidateROLIE validates doc against the ROLIE feed JSON schema.
func ValidateROLIE(doc any) ([]string, error) {
	return v21.ValidateROLIE(doc)
}
