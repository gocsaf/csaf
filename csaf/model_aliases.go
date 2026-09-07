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

// SchemaURI and Version identify the supported CSAF advisory format.
const (
	SchemaURI = v21.SchemaURI
	Version   = string(v21.CSAFDocumentCSAFVersionA21)
)

// Branch is a node in a product tree.
type Branch = v21.Branch

// Branches contains product tree nodes.
type Branches = v21.BranchesT

// BranchCategory describes a branch's role in the product tree.
type BranchCategory = v21.BranchesTElemCategory

// Document contains advisory metadata.
type Document = v21.CSAFDocument

// Vulnerability describes a vulnerability in an advisory.
type Vulnerability = v21.CSAFVulnerabilitiesElem

// Feed declares a ROLIE feed in provider metadata.
type Feed = v21.ProviderDistributionsElemRolieFeedsElem

// Distribution describes a provider distribution mechanism.
type Distribution = v21.ProviderDistributionsElem

// ROLIE contains feed, service and category declarations.
type ROLIE = v21.ProviderDistributionsElemRolie

// JSONURL identifies a JSON document.
type JSONURL = v21.JsonURLT

// AggregatorCategory identifies an aggregator or lister.
type AggregatorCategory = v21.AggregatorAggregatorCategory

// Publisher describes an advisory or metadata publisher.
type Publisher = v21.PublisherT

// DocumentPublisher describes an advisory publisher.
type DocumentPublisher = Publisher

// PublisherContact contains publisher contact information.
type PublisherContact = v21.PublisherTContact

// Category identifies a publisher category.
type Category = v21.PublisherTCategory

// MetadataRole identifies an issuing party's role.
type MetadataRole = v21.ProviderRole

// MetadataVersion identifies the provider metadata format.
type MetadataVersion = v21.ProviderMetadataVersion

// PGPKey describes a public OpenPGP key.
type PGPKey = v21.ProviderPublicOpenpgpKeysElem

// Fingerprint contains an OpenPGP key fingerprint.
type Fingerprint = string

const (
	AggregatorAggregator        = v21.AggregatorAggregatorCategoryAggregator
	AggregatorLister            = v21.AggregatorAggregatorCategoryLister
	MetadataRoleProvider        = v21.ProviderRoleCSAFProvider
	MetadataRolePublisher       = v21.ProviderRoleCSAFPublisher
	MetadataRoleTrustedProvider = v21.ProviderRoleCSAFTrustedProvider
	MetadataVersion21           = v21.ProviderMetadataVersionA21
	CSAFCategoryCoordinator     = v21.PublisherTCategoryCoordinator
	CSAFCategoryDiscoverer      = v21.PublisherTCategoryDiscoverer
	CSAFCategoryMultiplier      = v21.PublisherTCategoryMultiplier
	CSAFCategoryOther           = v21.PublisherTCategoryOther
	CSAFCategoryTranslator      = v21.PublisherTCategoryTranslator
	CSAFCategoryUser            = v21.PublisherTCategoryUser
	CSAFCategoryVendor          = v21.PublisherTCategoryVendor
)

const CSAFBranchCategoryArchitecture = v21.BranchesTElemCategoryArchitecture

const CSAFBranchCategoryHostName = v21.BranchesTElemCategoryHostName

const CSAFBranchCategoryLanguage = v21.BranchesTElemCategoryLanguage

const CSAFBranchCategoryPatchLevel = v21.BranchesTElemCategoryPatchLevel

const CSAFBranchCategoryPlatform = v21.BranchesTElemCategoryPlatform

const CSAFBranchCategoryProductFamily = v21.BranchesTElemCategoryProductFamily

const CSAFBranchCategoryProductName = v21.BranchesTElemCategoryProductName

const CSAFBranchCategoryProductVersion = v21.BranchesTElemCategoryProductVersion

const CSAFBranchCategoryProductVersionRange = v21.BranchesTElemCategoryProductVersionRange

const CSAFBranchCategoryServicePack = v21.BranchesTElemCategoryServicePack

const CSAFBranchCategorySpecification = v21.BranchesTElemCategorySpecification

const CSAFBranchCategoryVendor = v21.BranchesTElemCategoryVendor
