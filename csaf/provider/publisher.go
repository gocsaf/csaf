// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package provider

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gocsaf/csaf/v3/internal/bare"
)

// DecodePublisher decodes a publisher JSON object for the specified CSAF
// version. Since PMD uses the publisher definition from that CSAF version,
// this function can also decode an advisory's publisher.
func DecodePublisher(metadataVersion string, data []byte) (ProviderPublisher, error) {
	var v version
	switch metadataVersion {
	case "2.0":
		v = version20
	case "2.1":
		v = version21
	default:
		return ProviderPublisher{}, fmt.Errorf("unsupported provider metadata version %q", metadataVersion)
	}
	var b bare.ProviderPublisher
	if err := json.Unmarshal(data, &b); err != nil {
		return ProviderPublisher{}, fmt.Errorf("publisher: %w", err)
	}
	p, err := fromBareProviderPublisher(&b, v)
	if err != nil {
		return ProviderPublisher{}, fmt.Errorf("publisher: %w", err)
	}
	if err := checkProviderPublisher(&p, v); err != nil {
		return ProviderPublisher{}, fmt.Errorf("publisher: %w", err)
	}
	return p, nil
}

// Equal returns true if two [ProviderPublisher] instances are equal.
// Compares non-version specific fields, as well as version specific
// details (ContactDetails v2.0, Contact v2.1)
func (p *ProviderPublisher) Equal(o *ProviderPublisher) bool {
	if p.Category != o.Category ||
		p.Name != o.Name ||
		p.Namespace != o.Namespace ||
		deref(p.IssuingAuthority) != deref(o.IssuingAuthority) {
		return false
	}
	pd, p20 := p.ContactDetails()
	od, o20 := o.ContactDetails()
	pc, p21 := p.Contact()
	oc, o21 := o.Contact()
	return p20 == o20 && p21 == o21 &&
		deref(pd) == deref(od) &&
		pc.equal(oc)
}

// equal compares two [ContactT] instances field by field.
func (c *ContactT) equal(o *ContactT) bool {
	if c == nil {
		c = &ContactT{}
	}
	if o == nil {
		o = &ContactT{}
	}
	return deref(c.Details) == deref(o.Details) &&
		deref(c.Email) == deref(o.Email) &&
		deref(c.PublicOpenpgpKeyURL) == deref(o.PublicOpenpgpKeyURL) &&
		deref(c.URL) == deref(o.URL)
}

// deref returns the value of s or "" if s is nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// SetPGP sets the fingerprint and URL of the OpenPGP key
// of the feed. If the feed already has a key with
// given fingerprint the URL updated.
// If there is no such key it is append to the list of keys.
func (pmd *Provider) SetPGP(fingerprint, url string) {
	for i := range pmd.PublicOpenpgpKeys {
		key := &pmd.PublicOpenpgpKeys[i]
		if key.Fingerprint != nil && strings.EqualFold(*key.Fingerprint, fingerprint) {
			key.URL = url
			return
		}
	}
	pmd.PublicOpenpgpKeys = append(pmd.PublicOpenpgpKeys, ProviderPublicOpenpgpKeysElem{
		Fingerprint: &fingerprint,
		URL:         url,
	})
}
