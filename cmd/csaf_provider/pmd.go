// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/csaf/provider"
	v21 "github.com/gocsaf/csaf/v3/csaf/v21"
	"github.com/gocsaf/csaf/v3/internal/bare"
	"github.com/gocsaf/csaf/v3/util"
)

const (
	roleTrustedProvider = "csaf_trusted_provider"
	// maintenanceWarningWindow is the time window for warning
	// about maintaned_until deadline being reached (CSAF v2.1 only).
	maintenanceWarningWindow = 90 * 24 * time.Hour
)

// timestamp returns time as [v21.DateTime]
func timestamp(t time.Time) v21.DateTime {
	return v21.NewDateTime(t.UTC().Truncate(time.Second))
}

// newProviderMetadata creates the version specific PMD for [versionTree].
func (vtr *versionTree) newProviderMetadata(fingerprint string, now time.Time) (*provider.Provider, error) {
	pmd, err := provider.NewProviderMetadata(vtr.version)
	if err != nil {
		return nil, err
	}
	ts := timestamp(now)
	pmd.CanonicalURL = vtr.pmdURL()
	pmd.LastUpdated = ts
	pmd.Role = roleTrustedProvider
	pmd.ListOnCSAFAggregators = true
	pmd.MirrorOnCSAFAggregators = true
	vtr.cfg.ProviderMetaData.apply(pmd)

	var feeds []provider.ProviderDistributionsElemRolieFeedsElem
	for _, t := range vtr.feedTLPs() {
		feed, err := pmd.NewFeed()
		if err != nil {
			return nil, err
		}
		summary := "TLP:" + t.label() + " advisories"
		feed.Summary = &summary
		feed.TLPLabel = t.label()
		feed.URL = vtr.feedURL(t)
		feed.SetLastUpdated(ts)
		feeds = append(feeds, feed)
	}
	if len(feeds) > 0 {
		dist, err := pmd.NewDistribution()
		if err != nil {
			return nil, err
		}
		dist.Rolie = &provider.ProviderDistributionsElemRolie{Feeds: feeds}
		pmd.Distributions = append(pmd.Distributions, dist)
	}

	if vtr.cfg.WriteIndices {
		for _, t := range vtr.feedTLPs() {
			dist, err := pmd.NewDistribution()
			if err != nil {
				return nil, err
			}
			url := vtr.url(string(t))
			switch vtr.version {
			case csafVersion20:
				u := provider.URLT(url)
				dist.SetDirectoryURL(&u)
			case csafVersion21:
				dist.SetDirectory(&provider.ProviderDistributionsElemDirectory{
					TLPLabel: provider.TLPLabelT(t.label()),
					URL:      provider.URLT21(url),
				})
			}
			pmd.Distributions = append(pmd.Distributions, dist)
		}
	}

	pmd.SetPGP(fingerprint, vtr.openPGPPublicURL(fingerprint))
	return pmd, nil
}

// apply applies configuration values to PMD
// version specific values are no-ops for wrong version PMD
func (pmdc *providerMetadataConfig) apply(pmd *provider.Provider) {
	if pmdc.ListOnCSAFAggregators != nil {
		pmd.ListOnCSAFAggregators = *pmdc.ListOnCSAFAggregators
	}
	if pmdc.MirrorOnCSAFAggregators != nil {
		pmd.MirrorOnCSAFAggregators = *pmdc.MirrorOnCSAFAggregators
	}
	if pmdc.MaintainedFrom != nil {
		from := timestamp(*pmdc.MaintainedFrom)
		pmd.SetMaintainedFrom(&from)
	}
	if pmdc.MaintainedUntil != nil {
		until := timestamp(*pmdc.MaintainedUntil)
		pmd.SetMaintainedUntil(&until)
	}
	if pc := pmdc.Publisher; pc != nil {
		p := &pmd.Publisher
		p.Category = pc.Category
		p.IssuingAuthority = pc.IssuingAuthority
		p.Name = pc.Name
		p.Namespace = pc.Namespace
		p.SetContact(pc.Contact)
		p.SetContactDetails(pc.ContactDetails)
	}
}

// setLastUpdated sets last_updated for CSAF 2.1 feeds
// no-op for 2.0 PMDs
func setLastUpdated(pmd *provider.Provider, feedURL string, ts v21.DateTime) error {
	if pmd.MetadataVersion != csafVersion21 {
		return nil
	}
	found := false
	for i := range pmd.Distributions {
		if r := pmd.Distributions[i].Rolie; r != nil {
			for j := range r.Feeds {
				if r.Feeds[j].URL == feedURL {
					r.Feeds[j].SetLastUpdated(ts)
					found = true
				}
			}
		}
	}
	if !found {
		return fmt.Errorf("%s: feed not found in PMD", feedURL)
	}
	return nil
}

// checkMaintenanceWindow makes a v2.1 PMD check on the maintenance window defined by maintained_from/maintained_until fields.
func checkMaintenanceWindow(pmd *provider.Provider, now time.Time) []string {
	var warnings []string
	if from, _ := pmd.MaintainedFrom(); from != nil {
		t, err := from.Time()
		if err == nil && now.Before(t) {
			warnings = append(warnings, fmt.Sprintf("PMD not yet maintained, start from: %s", *from))
		}
	}
	if until, _ := pmd.MaintainedUntil(); until != nil {
		if t, err := until.Time(); err == nil {
			switch {
			case now.After(t):
				warnings = append(warnings, fmt.Sprintf("%s: mainted_until deadline %s exceeded", pmd.CanonicalURL, *until))
			case t.Sub(now) < maintenanceWarningWindow:
				warnings = append(warnings, fmt.Sprintf("%s: PMD maintained_until window closes in less than 90 days: %s", pmd.CanonicalURL, *until))
			}
		}
	}
	return warnings
}

// loadPMD loads the PMD of the [versionTree].
func (vtr *versionTree) loadPMD() (*provider.Provider, error) {
	path := vtr.pmdPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := validatePMD(doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var b bare.Provider
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	pmd, err := provider.FromBare(&b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if pmd.MetadataVersion != vtr.version {
		return nil, fmt.Errorf(
			"%s has metadata_version %q, but is configured for CSAF %s",
			path, pmd.MetadataVersion, vtr.version)
	}
	return pmd, nil
}

// writePMD writes PMD to specified path after check and validation.
func writePMD(path string, pmd *provider.Provider) error {
	if err := pmd.Check(); err != nil {
		return fmt.Errorf("invalid PMD: %w", err)
	}
	raw, err := json.MarshalIndent(pmd, "", "  ")
	if err != nil {
		return err
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	if err := validatePMD(doc); err != nil {
		return fmt.Errorf("invalid PMD: %w", err)
	}

	name, f, err := util.MakeUniqFile(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		f.Close()
		os.Remove(name)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// validatePMD validates PMD doc based on contained metadata_version.
func validatePMD(doc any) error {
	msgs, err := csaf.ValidateProviderMetadata(doc)
	if err != nil {
		return err
	}
	if len(msgs) > 0 {
		return errors.New(strings.Join(msgs, "; "))
	}
	return nil
}
