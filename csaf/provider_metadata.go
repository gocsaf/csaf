// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package csaf

import (
	"io"

	v21 "github.com/gocsaf/csaf/v3/csaf/v21"
)

// ProviderMetadata is CSAF 2.1 provider metadata.
type ProviderMetadata = v21.Provider

// ProviderPublisherCategory identifies a provider publisher category.
type ProviderPublisherCategory = v21.PublisherTCategory

const ProviderPublisherCategoryVendor = v21.PublisherTCategoryVendor

// NewProviderMetadata creates CSAF 2.1 provider metadata.
func NewProviderMetadata(canonicalURL string) *ProviderMetadata {
	return v21.NewProviderMetadata(canonicalURL)
}

// NewProviderMetadataDomain creates provider metadata below a domain's
// well-known CSAF path.
func NewProviderMetadataDomain(domain string, labels []TLPLabel) *ProviderMetadata {
	return v21.NewProviderMetadataDomain(domain, providerTLPLabels(labels))
}

// NewProviderMetadataPrefix creates provider metadata below prefix.
func NewProviderMetadataPrefix(prefix string, labels []TLPLabel) *ProviderMetadata {
	return v21.NewProviderMetadataPrefix(prefix, providerTLPLabels(labels))
}

// LoadProviderMetadata validates and decodes CSAF 2.1 provider metadata.
func LoadProviderMetadata(reader io.Reader) (*ProviderMetadata, error) {
	return v21.LoadProviderMetadata(reader)
}

func providerTLPLabels(labels []TLPLabel) []v21.TLPLabelT {
	converted := make([]v21.TLPLabelT, len(labels))
	for i, label := range labels {
		converted[i] = v21.TLPLabelT(label)
	}
	return converted
}
