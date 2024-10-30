// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gocsaf/csaf/v3/util"
)

type (
	baseReporter struct {
		num         int
		description string
	}
	validReporter             struct{ baseReporter }
	filenameReporter          struct{ baseReporter }
	tlsReporter               struct{ baseReporter }
	tlpWhiteReporter          struct{ baseReporter }
	tlpAmberRedReporter       struct{ baseReporter }
	redirectsReporter         struct{ baseReporter }
	providerMetadataReport    struct{ baseReporter }
	securityReporter          struct{ baseReporter }
	wellknownMetadataReporter struct{ baseReporter }
	dnsPathReporter           struct{ baseReporter }
	oneFolderPerYearReport    struct{ baseReporter }
	indexReporter             struct{ baseReporter }
	changesReporter           struct{ baseReporter }
	directoryListingsReporter struct{ baseReporter }
	rolieFeedReporter         struct{ baseReporter }
	rolieServiceReporter      struct{ baseReporter }
	rolieCategoryReporter     struct{ baseReporter }
	integrityReporter         struct{ baseReporter }
	signaturesReporter        struct{ baseReporter }
	publicPGPKeyReporter      struct{ baseReporter }
	listReporter              struct{ baseReporter }
	hasTwoReporter            struct{ baseReporter }
	mirrorReporter            struct{ baseReporter }
)

var reporters = [...]reporter{
	1:  &validReporter{baseReporter{num: 1, description: "Valid CSAF documents"}},
	2:  &filenameReporter{baseReporter{num: 2, description: "Filename"}},
	3:  &tlsReporter{baseReporter{num: 3, description: "TLS"}},
	4:  &tlpWhiteReporter{baseReporter{num: 4, description: "TLP:WHITE"}},
	5:  &tlpAmberRedReporter{baseReporter{num: 5, description: "TLP:AMBER and TLP:RED"}},
	6:  &redirectsReporter{baseReporter{num: 6, description: "Redirects"}},
	7:  &providerMetadataReport{baseReporter{num: 7, description: "provider-metadata.json"}},
	8:  &securityReporter{baseReporter{num: 8, description: "security.txt"}},
	9:  &wellknownMetadataReporter{baseReporter{num: 9, description: "/.well-known/csaf/provider-metadata.json"}},
	10: &dnsPathReporter{baseReporter{num: 10, description: "DNS path"}},
	11: &oneFolderPerYearReport{baseReporter{num: 11, description: "One folder per year"}},
	12: &indexReporter{baseReporter{num: 12, description: "index.txt"}},
	13: &changesReporter{baseReporter{num: 13, description: "changes.csv"}},
	14: &directoryListingsReporter{baseReporter{num: 14, description: "Directory listings"}},
	15: &rolieFeedReporter{baseReporter{num: 15, description: "ROLIE feed"}},
	16: &rolieServiceReporter{baseReporter{num: 16, description: "ROLIE service document"}},
	17: &rolieCategoryReporter{baseReporter{num: 17, description: "ROLIE category document"}},
	18: &integrityReporter{baseReporter{num: 18, description: "Integrity"}},
	19: &signaturesReporter{baseReporter{num: 19, description: "Signatures"}},
	20: &publicPGPKeyReporter{baseReporter{num: 20, description: "Public OpenPGP Key"}},
	21: &listReporter{baseReporter{num: 21, description: "List of CSAF providers"}},
	22: &hasTwoReporter{baseReporter{num: 22, description: "Two disjoint issuing parties"}},
	23: &mirrorReporter{baseReporter{num: 23, description: "Mirror"}},
}

func (bc *baseReporter) requirement(domain *Domain) *Requirement {
	req := &Requirement{
		Num:         bc.num,
		Description: bc.description,
	}
	domain.Requirements = append(domain.Requirements, req)
	return req
}

// contains returns whether any of vs is present in s.
func containsAny[E comparable](s []E, vs ...E) bool {
	for _, e := range s {
		for _, v := range vs {
			if e == v {
				return true
			}
		}
	}
	return false
}

// report reports if there where any invalid filenames,
func (r *validReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if p.validator == nil {
		req.message(WarnType, "No remote validator configured")
	}
	switch {
	case !p.invalidAdvisories.used():
		req.message(InfoType, "No validations performed")
	case len(p.invalidAdvisories) == 0:
		if p.validator != nil && containsAny(p.cfg.RemoteValidatorPresets,
			"basic", "mandatory", "extended", "full") {
			req.message(InfoType, "All advisories validated fine.")
		} else {
			req.message(InfoType, "All advisories validated fine against the schema.")
		}
	default:
		req.Append(p.invalidAdvisories)
	}
}

// report reports if there where any bad filename.
func (r *filenameReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badFilenames.used() {
		req.message(InfoType, "No filenames checked for conformance")
	} else if len(p.badFilenames) == 0 {
		req.message(InfoType, "All found filenames are conforming.")
	} else {
		req.Append(p.badFilenames)
	}
}

// report tests if the URLs are HTTPS and sets the "message" field value
// of the "Requirement" struct as a result of that.
// A list of non HTTPS URLs is included in the value of the "message" field.
func (r *tlsReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if p.noneTLS == nil {
		req.message(InfoType, "No TLS checks performed.")
		return
	}
	if len(p.noneTLS) == 0 {
		req.message(InfoType, "All tested URLs were HTTPS.")
		return
	}

	urls := make([]string, len(p.noneTLS))
	var i int
	for k := range p.noneTLS {
		urls[i] = k
		i++
	}
	sort.Strings(urls)
	req.message(ErrorType, "Following non-HTTPS URLs were used:")
	req.message(ErrorType, urls...)
}

// report tests if a document labeled TLP:WHITE
// is freely accessible and sets the "message" field value
// of the "Requirement" struct as a result of that.
func (r *tlpWhiteReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badWhitePermissions.used() {
		req.message(InfoType, "No access-protected advisories labeled TLP:WHITE found.")
		return
	}
	if len(p.badWhitePermissions) == 0 {
		req.message(InfoType, "All advisories labeled TLP:WHITE were freely accessible.")
		return
	}
	req.Messages = p.badWhitePermissions
}

// report tests if a document labeled TLP:AMBER
// or TLP:RED is access protected
// and sets the "message" field value
// of the "Requirement" struct as a result of that.
func (r *tlpAmberRedReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badAmberRedPermissions.used() {
		req.message(InfoType, "No advisories labeled TLP:AMBER or TLP:RED tested for accessibility.")
		return
	}
	if len(p.badAmberRedPermissions) == 0 {
		req.message(InfoType, "All tested advisories labeled TLP:WHITE or TLP:RED were access-protected.")
		return
	}
	req.Messages = p.badAmberRedPermissions
}

// report tests if redirects are used and sets the "message" field value
// of the "Requirement" struct as a result of that.
func (r *redirectsReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if len(p.redirects) == 0 {
		req.message(InfoType, "No redirections found.")
		return
	}

	keys := keysNotInValues(p.redirects)

	first := func(i int) string {
		if vs := p.redirects[keys[i]]; len(vs) > 0 {
			return vs[0]
		}
		return ""
	}

	sort.Slice(keys, func(i, j int) bool { return first(i) < first(j) })

	for i, k := range keys {
		keys[i] = fmt.Sprintf("Redirect %s -> %s", strings.Join(p.redirects[k], " -> "), k)
	}
	req.message(WarnType, keys...)
}

// keysNotInValues returns a slice of keys which are not in the values
// of the given map.
func keysNotInValues(m map[string][]string) []string {
	values := util.Set[string]{}
	for _, vs := range m {
		for _, v := range vs {
			values.Add(v)
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if !values.Contains(k) {
			keys = append(keys, k)
		}
	}
	return keys
}

// report tests if an provider-metadata.json are available and sets the
// "message" field value of the "Requirement" struct as a result of that.
func (r *providerMetadataReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badProviderMetadata.used() {
		req.message(InfoType, "No provider-metadata.json checked.")
		return
	}
	if len(p.badProviderMetadata) == 0 {
		req.message(InfoType, "Found good provider metadata.")
		return
	}
	req.Messages = p.badProviderMetadata
}

// report tests the "security.txt" file and sets the "message" field value
// of the "Requirement" struct as a result of that.
func (r *securityReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badSecurity.used() {
		req.message(WarnType, "Performed no in-depth test of security.txt.")
		return
	}
	req.Messages = p.badSecurity
}

// report tests the availability of the "provider-metadata.json" under /.well-known/csaf/ directoy.
func (r *wellknownMetadataReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badWellknownMetadata.used() {
		req.message(WarnType, "Since no valid provider-metadata.json was found, no extended check was performed.")
		return
	}
	if len(p.badWellknownMetadata) == 0 {
		req.message(InfoType, "Found /.well-known/csaf/provider-metadata.json")
		return
	}
	req.Messages = p.badWellknownMetadata
}

// report outputs the result of the the explicit DNS test.
func (r *dnsPathReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badDNSPath.used() {
		req.message(WarnType, "No check about contents from https://csaf.data.security.DOMAIN performed.")
		return
	}
	if len(p.badDNSPath) == 0 {
		req.message(InfoType, "https://csaf.data.security.DOMAIN is available and serves the provider-metadata.json.")
		return
	}
	req.Messages = p.badDNSPath
}

func (r *oneFolderPerYearReport) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if len(p.badFolders) == 0 {
		req.message(InfoType, "All CSAF files are in the right folders.")
		return
	}
	req.Messages = p.badFolders
}

func (r *indexReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badIndices.used() {
		req.message(ErrorType, "No index.txt checked.")
		return
	}
	if len(p.badIndices) == 0 {
		req.message(InfoType, "Found good index.txt.")
		return
	}
	req.Messages = p.badIndices
}

func (r *changesReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badChanges.used() {
		req.message(ErrorType, "No changes.csv checked.")
		return
	}
	if len(p.badChanges) == 0 {
		req.message(InfoType, "Found good changes.csv.")
		return
	}
	req.Messages = p.badChanges
}

func (r *directoryListingsReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badDirListings.used() {
		req.message(WarnType, "No directory listings checked.")
		return
	}
	if len(p.badDirListings) == 0 {
		req.message(InfoType, "All directory listings are valid.")
		return
	}
	req.Messages = p.badDirListings
}

// report checks whether there is only a single ROLIE feed for a
// given TLP level and whether any of the TLP levels
// TLP:WHITE, TLP:GREEN or unlabeled exists and sets the "message" field value
// of the "Requirement" struct as a result of that.
func (r *rolieFeedReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if len(p.badROLIEFeed) == 0 {
		req.message(InfoType, "All checked ROLIE feeds validated fine.")
		return
	}
	req.Messages = p.badROLIEFeed
}

// report tests whether a ROLIE service document is used and if so,
// whether it is a [RFC8322] conform JSON file that lists the
// ROLIE feed documents and sets the "message" field value
// of the "Requirement" struct as a result of that.
func (r *rolieServiceReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badROLIEService.used() {
		req.message(WarnType, "ROLIE service document was not checked.")
		return
	}
	if len(p.badROLIEService) == 0 {
		req.message(InfoType, "ROLIE service document validated fine.")
		return
	}
	req.Messages = p.badROLIEService

}

// report tests whether a ROLIE category document is used and if so,
// whether it is a [RFC8322] conform JSON file and is used to dissect
// documents by certain criteria
// and sets the "message" field value
// of the "Requirement" struct as a result of that.
func (r *rolieCategoryReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badROLIECategory.used() {
		req.message(WarnType, "No checks on the existence of ROLIE category documents performed.")
		return
	}
	if len(p.badROLIECategory) == 0 {
		req.message(InfoType, "All checked ROLIE category documents exist.")
		return
	}
	req.Messages = p.badROLIECategory

}

func (r *integrityReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badIntegrities.used() {
		req.message(InfoType, "No checksums checked.")
		return
	}
	if len(p.badIntegrities) == 0 {
		req.message(InfoType, "All checksums match.")
		return
	}
	req.Messages = p.badIntegrities
}

func (r *signaturesReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badSignatures.used() {
		req.message(InfoType, "No signatures checked.")
		return
	}
	req.Messages = p.badSignatures
	if len(p.badSignatures) == 0 {
		req.message(InfoType, "All signatures verified.")
	}
}

func (r *publicPGPKeyReporter) report(p *processor, domain *Domain) {
	req := r.requirement(domain)
	if !p.badPGPs.used() {
		req.message(InfoType, "No public OpenPGP keys loaded.")
		return
	}
	req.Messages = p.badPGPs
	if p.keys != nil {
		req.message(InfoType, fmt.Sprintf("%d public OpenPGP key(s) loaded.",
			p.keys.CountEntities()))
	}
}

// report tests whether a CSAF aggregator JSON schema conform
// aggregator.json exists without being adjacent to a
// provider-metadata.json
func (r *listReporter) report(_ *processor, _ *Domain) {
	// TODO
}

// report tests whether the aggregator.json lists at least
// two disjoint issuing parties. TODO: reevaluate phrasing (Req 7.1.22)
func (r *hasTwoReporter) report(_ *processor, _ *Domain) {
	// TODO
}

// report tests whether the CSAF documents of each issuing mirrored party
// is in a different folder, which are adjacent to the aggregator.json and
// if the folder name is retrieved from the name of the issuing authority.
// It also tests whether each folder has a provider-metadata.json for their
// party and provides ROLIE feed documents.
func (r *mirrorReporter) report(_ *processor, _ *Domain) {
	// TODO
}
