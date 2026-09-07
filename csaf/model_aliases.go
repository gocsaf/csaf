// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package csaf

import v21 "github.com/gocsaf/csaf/v3/csaf/v21"

// Advisory is a CSAF 2.1 advisory document.
type Advisory = v21.CSAF

// ProductTree contains the products described by a CSAF 2.1 advisory.
type ProductTree = v21.CSAFProductTree

// ProductID identifies a product within an advisory.
type ProductID = v21.ProductIDT

// FullProductName describes and identifies a product.
type FullProductName = v21.FullProductNameT

// ProductIdentificationHelper contains machine-readable product identifiers.
type ProductIdentificationHelper = v21.FullProductNameTProductIdentificationHelper

// PURL is a package URL from a product identification helper.
type PURL = string

// AggregatorAggregatorCategory identifies whether an aggregator document is
// produced by an aggregator or a lister.
type AggregatorAggregatorCategory = v21.AggregatorAggregatorCategory

const (
	AggregatorAggregatorCategoryAggregator = v21.AggregatorAggregatorCategoryAggregator
	AggregatorAggregatorCategoryLister     = v21.AggregatorAggregatorCategoryLister
)

// JsonURLT contains the URL of a JSON document.
type JsonURLT = v21.JsonURLT

// ProviderPublicOpenpgpKeysElem describes a public OpenPGP key published in
// CSAF 2.1 provider metadata.
type ProviderPublicOpenpgpKeysElem = v21.ProviderPublicOpenpgpKeysElem

// ProviderRole identifies the issuing party role in CSAF 2.1 provider
// metadata.
type ProviderRole = v21.ProviderRole

const (
	ProviderRoleCSAFProvider        = v21.ProviderRoleCSAFProvider
	ProviderRoleCSAFPublisher       = v21.ProviderRoleCSAFPublisher
	ProviderRoleCSAFTrustedProvider = v21.ProviderRoleCSAFTrustedProvider
)

// ProviderPublisher contains publisher information from CSAF 2.1 provider
// metadata.
type ProviderPublisher = v21.PublisherT

// ProviderDistributionsElemRolieFeedsElem contains one ROLIE feed declaration
// from CSAF 2.1 provider metadata.
type ProviderDistributionsElemRolieFeedsElem = v21.ProviderDistributionsElemRolieFeedsElem
