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
func DecodePublisher(metadataVersion string, data []byte) (Publisher, error) {
	var v version
	switch metadataVersion {
	case "2.0":
		v = version20
	case "2.1":
		v = version21
	default:
		return Publisher{}, fmt.Errorf("unsupported provider metadata version %q", metadataVersion)
	}
	var b bare.ProviderPublisher
	if err := json.Unmarshal(data, &b); err != nil {
		return Publisher{}, fmt.Errorf("publisher: %w", err)
	}
	p, err := fromBarePublisher(&b, v)
	if err != nil {
		return Publisher{}, fmt.Errorf("publisher: %w", err)
	}
	if err := p.Check(v); err != nil {
		return Publisher{}, fmt.Errorf("publisher: %w", err)
	}
	return p, nil
}

// Equal returns true if two [Publisher] instances are equal.
// Compares non-version specific fields, as well as version specific
// details (ContactDetails v2.0, Contact v2.1)
func (p *Publisher) Equal(o *Publisher) bool {
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

// equal compares two [Contact] instances field by field.
func (c *Contact) equal(o *Contact) bool {
	if c == nil {
		c = &Contact{}
	}
	if o == nil {
		o = &Contact{}
	}
	return deref(c.Details) == deref(o.Details) &&
		deref(c.Email) == deref(o.Email) &&
		deref(c.PublicOpenPGPKeyURL) == deref(o.PublicOpenPGPKeyURL) &&
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
func (pmd *ProviderMetadata) SetPGP(fingerprint, url string) {
	for i := range pmd.PublicOpenPGPKeys {
		key := &pmd.PublicOpenPGPKeys[i]
		if key.Fingerprint != nil && strings.EqualFold(*key.Fingerprint, fingerprint) {
			key.URL = URL(url)
			return
		}
	}
	pmd.PublicOpenPGPKeys = append(pmd.PublicOpenPGPKeys, OpenPGPKey{
		Fingerprint: &fingerprint,
		URL:         URL(url),
	})
}
