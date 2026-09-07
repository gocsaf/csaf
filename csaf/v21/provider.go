// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package v21

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/util"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SetLastUpdated updates the provider metadata timestamp.
func (provider *Provider) SetLastUpdated(value time.Time) {
	provider.LastUpdated = NewDateTime(value.UTC())
}

// SetPGP adds or updates a public OpenPGP key by fingerprint.
func (provider *Provider) SetPGP(fingerprint, url string) {
	for i := range provider.PGPKeys {
		key := &provider.PGPKeys[i]
		if strings.EqualFold(key.Fingerprint, fingerprint) {
			key.URL = URLT(url)
			return
		}
	}
	provider.PGPKeys = append(
		provider.PGPKeys,
		ProviderPublicOpenpgpKeysElem{
			Fingerprint: fingerprint,
			URL:         URLT(url),
		},
	)
}

// AddDirectoryDistribution adds a directory distribution unless its URL and
// TLP label are already present.
func (provider *Provider) AddDirectoryDistribution(url string, label TLPLabelT) {
	for i := range provider.Distributions {
		directory := provider.Distributions[i].Directory
		if directory != nil && directory.URL == URLT(url) && directory.TLPLabel == label {
			return
		}
	}
	provider.Distributions = append(provider.Distributions, ProviderDistributionsElem{
		Directory: &ProviderDistributionsElemDirectory{
			TLPLabel: label,
			URL:      URLT(url),
		},
	})
}

// WriteTo writes indented provider metadata JSON.
func (provider *Provider) WriteTo(writer io.Writer) (int64, error) {
	countingWriter := util.NWriter{Writer: writer}
	encoder := json.NewEncoder(&countingWriter)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(provider)
	return countingWriter.N, err
}

// NewProviderMetadata creates CSAF 2.1 provider metadata with defaults.
func NewProviderMetadata(canonicalURL string) *Provider {
	provider := &Provider{
		Schema:                  ProviderSchemaHttpsDocsOasisOpenOrgCSAFCSAFV21SchemaProviderJson,
		CanonicalURL:            ProviderURLT(canonicalURL),
		ListOnCSAFAggregators:   true,
		MetadataVersion:         ProviderMetadataVersionA21,
		MirrorOnCSAFAggregators: true,
		Role:                    ProviderRoleCSAFTrustedProvider,
	}
	provider.SetLastUpdated(time.Now())
	return provider
}

// NewProviderMetadataDomain creates provider metadata below the well-known
// CSAF path of domain.
func NewProviderMetadataDomain(domain string, labels []TLPLabelT) *Provider {
	return NewProviderMetadataPrefix(domain+"/.well-known/csaf", labels)
}

// NewProviderMetadataPrefix creates provider metadata and one ROLIE feed for
// each supplied TLP label.
func NewProviderMetadataPrefix(prefix string, labels []TLPLabelT) *Provider {
	provider := NewProviderMetadata(prefix + "/provider-metadata.json")
	if len(labels) == 0 {
		return provider
	}

	feeds := make([]ProviderDistributionsElemRolieFeedsElem, len(labels))
	for i, label := range labels {
		labelName := strings.ToLower(string(label))
		summary := "TLP:" + string(label) + " advisories"
		feeds[i] = ProviderDistributionsElemRolieFeedsElem{
			LastUpdated: provider.LastUpdated,
			Summary:     &summary,
			TLPLabel:    label,
			URL: JsonURLT(
				prefix + "/" + labelName + "/csaf-feed-tlp-" + labelName + ".json",
			),
		}
	}

	provider.Distributions = []ProviderDistributionsElem{{
		Rolie: &ProviderDistributionsElemRolie{Feeds: feeds},
	}}
	return provider
}

// LoadProviderMetadata validates and decodes CSAF 2.1 provider metadata.
func LoadProviderMetadata(reader io.Reader) (*Provider, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decode provider metadata JSON: %w", err)
	}
	errors, err := ValidateProviderMetadata(value)
	if err != nil {
		return nil, err
	}
	if len(errors) != 0 {
		return nil, fmt.Errorf("validate provider metadata: %s", strings.Join(errors, "; "))
	}

	var provider Provider
	if err := json.Unmarshal(data, &provider); err != nil {
		return nil, fmt.Errorf("decode typed provider metadata: %w", err)
	}
	return &provider, nil
}

// Equals reports componentwise equality, including nil publishers.
func (publisher *PublisherT) Equals(other *PublisherT) bool {
	if publisher == nil || other == nil {
		return publisher == other
	}
	return publisher.Category == other.Category &&
		publisher.Name == other.Name && publisher.Namespace == other.Namespace &&
		publisherContactsEqual(publisher.Contact, other.Contact) &&
		optionalStringsEqual(publisher.IssuingAuthority, other.IssuingAuthority)
}

func publisherContactsEqual(
	left *PublisherTContact,
	right *PublisherTContact,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return optionalStringsEqual(left.Details, right.Details) &&
		optionalStringsEqual(left.Email, right.Email) &&
		optionalStringsEqual(left.PublicOpenpgpKeyURL, right.PublicOpenpgpKeyURL)
}

func optionalStringsEqual(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
