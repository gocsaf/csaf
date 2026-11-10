// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package aggregator

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gocsaf/csaf/v5/csaf/provider"
	"github.com/gocsaf/csaf/v5/internal/bare"
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

// DecodeAggregator decodes an aggregator.json as CSAF 2.0 or
// CSAF 2.1 Aggregator based on aggregator_version
func DecodeAggregator(raw []byte) (*Aggregator, error) {
	var b bare.Aggregator
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("aggregator: %w", err)
	}
	agg, err := FromBare(&b)
	if err != nil {
		return nil, fmt.Errorf("aggregator: %w", err)
	}
	if err := agg.Check(); err != nil {
		return nil, fmt.Errorf("aggregator: %w", err)
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
