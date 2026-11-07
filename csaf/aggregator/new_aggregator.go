// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package aggregator

import (
	"errors"
	"fmt"

	"github.com/gocsaf/csaf/v5/csaf/provider"
)

// NewAggregator returns a new [Aggregator] with details
// based on the given CSAF aggregator aggregator_version
func NewAggregator(aggregatorVersion string) (*Aggregator, error) {
	agg := &Aggregator{Version: AggregatorVersion(aggregatorVersion)}
	switch aggregatorVersion {
	case "2.0":
	case "2.1":
		agg.aggregator21Details = &aggregator21Details{
			Schema: AggregatorSchemaHttpsDocsOasisOpenOrgCSAFCSAFV21SchemaAggregatorJson,
		}
	default:
		return nil, fmt.Errorf("unsupported aggregator version %q", aggregatorVersion)
	}
	return agg, nil
}

// PublisherFromProvider returns publisher of an aggregator based on a PMD publisher of same CSAF version.
func PublisherFromProvider(p *provider.ProviderPublisher) (AggregatorCSAFProvidersElemMetadataPublisher, error) {
	ap := AggregatorCSAFProvidersElemMetadataPublisher{
		Category:         PublisherTCategory(p.Category),
		IssuingAuthority: p.IssuingAuthority,
		Name:             p.Name,
		Namespace:        p.Namespace,
	}
	contactDetails, is20 := p.ContactDetails()
	contact, is21 := p.Contact()
	switch {
	case is20:
		ap.aggregatorCSAFProvidersElemMetadataPublisher20Details = &aggregatorCSAFProvidersElemMetadataPublisher20Details{
			ContactDetails: contactDetails,
		}
	case is21:
		ap.aggregatorCSAFProvidersElemMetadataPublisher21Details = &aggregatorCSAFProvidersElemMetadataPublisher21Details{
			Contact: (*ContactT)(contact),
		}
	default:
		return ap, errors.New("no version specific details in publisher")
	}
	return ap, nil
}
