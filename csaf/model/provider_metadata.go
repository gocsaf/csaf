// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package model

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gocsaf/csaf/v3/internal/bare"
)

type ProviderMetadata struct {
	Version                 SpecVersion
	CanonicalURL            string
	ListOnCSAFAggregators   bool
	MirrorOnCSAFAggregators bool
	Role                    string
	Distributions           []Distribution
	PublicOpenpgpKeys       []PGPKey
}

type PGPKey struct {
	URL         string
	Fingerprint string
}

type Distribution struct {
	Directory Directory
	Rolie     *ROLIE
}

type ROLIE struct {
	Categories []string
	Feeds      []Feed
	Services   []string
}

type Feed struct {
	URL         string
	TLPLabel    string
	Summary     string
	LastUpdated *time.Time
}

type Directory interface {
	GetURL() string
	GetTLPLabel() (label string, ok bool)
}

type dir20 string

func (d dir20) GetURL() string            { return string(d) }
func (dir20) GetTLPLabel() (string, bool) { return "", false }

type dir21 struct {
	TLP string `json:"tlp_label"`
	URL string `json:"url"`
}

func (d *dir21) GetURL() string              { return d.URL }
func (d *dir21) GetTLPLabel() (string, bool) { return d.TLP, true }

func NewPMD(data []byte) (*ProviderMetadata, error) {
	var bpmd bare.Provider
	if err := json.Unmarshal(data, &bpmd); err != nil {
		return nil, err
	}
	version := SpecVersion(bpmd.MetadataVersion)
	switch version {
	case Version20, Version21:
	default:
		return nil, fmt.Errorf("metadata_version %q not known", bpmd.MetadataVersion)
	}

	pmd := &ProviderMetadata{
		Version:                 version,
		CanonicalURL:            bpmd.CanonicalURL,
		ListOnCSAFAggregators:   bpmd.ListOnCSAFAggregators,
		MirrorOnCSAFAggregators: bpmd.MirrorOnCSAFAggregators,
		Role:                    bpmd.Role,
		Distributions:           make([]Distribution, 0, len(bpmd.Distributions)),
		PublicOpenpgpKeys:       make([]PGPKey, 0, len(bpmd.PublicOpenpgpKeys)),
	}

	for i := range bpmd.Distributions {
		distElem := &bpmd.Distributions[i]
		dir, err := decodeDirectory(distElem, version)
		if err != nil {
			return nil, err
		}
		rolie, err := convertROLIE(distElem.Rolie, version)
		if err != nil {
			return nil, err
		}
		pmd.Distributions = append(pmd.Distributions, Distribution{Directory: dir, Rolie: rolie})
	}
	for _, key := range bpmd.PublicOpenpgpKeys {
		fp, err := decodeFingerprint(key.Fingerprint)
		if err != nil {
			return nil, err
		}
		pmd.PublicOpenpgpKeys = append(pmd.PublicOpenpgpKeys, PGPKey{URL: key.URL, Fingerprint: fp})
	}
	return pmd, nil
}

func decodeDirectory(distElem *bare.ProviderDistributionsElem, version SpecVersion) (Directory, error) {
	switch version {
	case Version20:
		if len(distElem.DirectoryURL) == 0 {
			return nil, nil
		}
		var d dir20
		if err := json.Unmarshal(distElem.DirectoryURL, &d); err != nil {
			return nil, fmt.Errorf("unmarshalling directory_url: %w", err)
		}
		return d, nil
	default:
		if len(distElem.Directory) == 0 {
			return nil, nil
		}
		d := new(dir21)
		if err := json.Unmarshal(distElem.Directory, d); err != nil {
			return nil, fmt.Errorf("unmarshalling directory: %w", err)
		}
		return d, nil
	}
}

func decodeFingerprint(raw json.RawMessage) (string, error) {
	var f string
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &f); err != nil {
			return "", fmt.Errorf("unmarshalling fingerprint: %w", err)
		}
	}
	return f, nil
}

func convertROLIE(rolieElem *bare.ProviderDistributionsElemRolie, version SpecVersion) (*ROLIE, error) {
	if rolieElem == nil {
		return nil, nil
	}
	rolie := &ROLIE{
		Categories: rolieElem.Categories,
		Services:   rolieElem.Services,
		Feeds:      make([]Feed, 0, len(rolieElem.Feeds)),
	}
	for _, feedElem := range rolieElem.Feeds {
		feed := Feed{URL: feedElem.URL, TLPLabel: feedElem.TLPLabel}
		if feedElem.Summary != nil {
			feed.Summary = *feedElem.Summary
		}
		if version == Version21 {
			var t time.Time
			if err := json.Unmarshal(feedElem.LastUpdated, &t); err != nil {
				return nil, fmt.Errorf("unmarshalling feed %q last_updated: %w", feedElem.URL, err)
			}
			feed.LastUpdated = &t
		}
		rolie.Feeds = append(rolie.Feeds, feed)
	}
	return rolie, nil
}
