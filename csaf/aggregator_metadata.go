// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package csaf

import (
	"time"

	v21 "github.com/gocsaf/csaf/v3/csaf/v21"
)

// Aggregator is CSAF 2.1 aggregator metadata.
type Aggregator = v21.Aggregator

// AggregatorInfo describes the aggregator publishing the metadata.
type AggregatorInfo = v21.AggregatorAggregator

// AggregatorCSAFProvider is one provider entry in aggregator metadata.
type AggregatorCSAFProvider = v21.AggregatorCSAFProvidersElem

// AggregatorCSAFPublisher is one publisher entry in aggregator metadata.
type AggregatorCSAFPublisher = v21.AggregatorCSAFPublishersElem

// AggregatorCSAFProviderMetadata contains metadata shared by provider and
// publisher entries.
type AggregatorCSAFProviderMetadata = v21.MetadataT

// AggregatorVersion identifies the aggregator metadata specification version.
type AggregatorVersion = v21.AggregatorAggregatorVersion

const AggregatorVersion21 = v21.AggregatorAggregatorVersionA21

// AggregatorURL contains the canonical URL of aggregator metadata.
type AggregatorURL = v21.AggregatorURLT

// ProviderURL contains the URL of provider metadata.
type ProviderURL = v21.ProviderURLT

// URLT contains a URL used by CSAF 2.1 metadata.
type URLT = v21.URLT

// AggregatorRole identifies the role of an aggregator entry.
type AggregatorRole = v21.RoleT

// DateTime is a CSAF 2.1 date-time value.
type DateTime = v21.DateTime

// NewDateTime creates a CSAF 2.1 date-time value.
func NewDateTime(value time.Time) DateTime {
	return v21.NewDateTime(value)
}

const AggregatorSchema21 = v21.AggregatorSchemaHttpsDocsOasisOpenOrgCSAFCSAFV21SchemaAggregatorJson
