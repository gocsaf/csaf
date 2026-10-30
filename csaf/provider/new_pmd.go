// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package provider

import (
	"fmt"
)

// NewProviderMetadata returns a new [Provider] with details
// based on the given CSAF provider metadata version
func NewProviderMetadata(metadataVersion string) (*Provider, error) {
	pmd := &Provider{MetadataVersion: metadataVersion}
	switch metadataVersion {
	case "2.0":
		pmd.Publisher.providerPublisher20Details = &providerPublisher20Details{}
	case "2.1":
		pmd.Publisher.providerPublisher21Details = &providerPublisher21Details{}
		pmd.provider21Details = &provider21Details{
			Schema: ProviderSchemaHttpsDocsOasisOpenOrgCSAFCSAFV21SchemaProviderJson,
		}
	default:
		return nil, fmt.Errorf("unsupported provider metadata version %q", metadataVersion)
	}
	return pmd, nil
}

// NewDistribution returns a new [ProviderDistributionsElem] with details
// based on the given CSAF provider metadata version
func (pmd *Provider) NewDistribution() (ProviderDistributionsElem, error) {
	var dist ProviderDistributionsElem
	switch pmd.MetadataVersion {
	case "2.0":
		dist.providerDistributionsElem20Details = &providerDistributionsElem20Details{}
	case "2.1":
		dist.providerDistributionsElem21Details = &providerDistributionsElem21Details{}
	default:
		return dist, fmt.Errorf("unsupported provider metadata version %q", pmd.MetadataVersion)
	}
	return dist, nil
}

// NewFeed returns a new  [ProviderDistributionsElemRolieFeedsElem] based on
// CSAF provider metadata version with specific details for Version 2.1
func (pmd *Provider) NewFeed() (ProviderDistributionsElemRolieFeedsElem, error) {
	var feed ProviderDistributionsElemRolieFeedsElem
	switch pmd.MetadataVersion {
	case "2.0":
	case "2.1":
		feed.providerDistributionsElemRolieFeedsElem21Details = &providerDistributionsElemRolieFeedsElem21Details{}
	default:
		return feed, fmt.Errorf("unsupported provider metadata version %q", pmd.MetadataVersion)
	}
	return feed, nil
}
