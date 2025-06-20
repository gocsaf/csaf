// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"errors"
	"github.com/gocsaf/csaf/v3/internal/misc"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

// identifier consist of document/tracking/id and document/publisher/namespace,
// which in sum are unique for each csaf document and the name of a csaf document
type identifier struct {
	id        string
	namespace string
}

// String implements fmt.Stringer
func (id identifier) String() string {
	return "(" + id.namespace + ", " + id.id + ")"
}

// labelChecker helps to check if advisories are of the right TLP color.
type labelChecker struct {
	feedURL   string
	feedLabel csaf.TLPLabel

	advisories      map[csaf.TLPLabel]util.Set[string]
	whiteAdvisories map[identifier]bool
}

// reset brings the checker back to an initial state.
func (lc *labelChecker) reset() {
	lc.feedLabel = ""
	lc.feedURL = ""
	lc.advisories = map[csaf.TLPLabel]util.Set[string]{}
	lc.whiteAdvisories = map[identifier]bool{}
}

// tlpLevel returns an inclusion order of TLP colors.
func tlpLevel(label csaf.TLPLabel) int {
	switch label {
	case csaf.TLPLabelWhite:
		return 1
	case csaf.TLPLabelGreen:
		return 2
	case csaf.TLPLabelAmber:
		return 3
	case csaf.TLPLabelRed:
		return 4
	default:
		return 0
	}
}

// extractTLP extracts the tlp label of the given document
// and defaults to UNLABELED if not found.
func (p *processor) extractTLP(doc any) csaf.TLPLabel {
	labelString, err := p.expr.Eval(`$.document.distribution.tlp.label`, doc)
	if err != nil {
		return csaf.TLPLabelUnlabeled
	}
	label, ok := labelString.(string)
	if !ok {
		return csaf.TLPLabelUnlabeled
	}
	return csaf.TLPLabel(label)
}

// check tests if the TLP label of an advisory is used correctly.
func (lc *labelChecker) check(
	p *processor,
	doc any,
	url string,
) {
	label := p.extractTLP(doc)

	// Check the permissions.
	lc.checkPermissions(p, label, doc, url)

	// Associate advisory label to urls.
	lc.add(label, url)

	// If entry shows up in feed of higher tlp level, give out info or warning.
	lc.checkRank(p, label, url)
}

// checkPermissions checks for mistakes in access-protection.
func (lc *labelChecker) checkPermissions(
	p *processor,
	label csaf.TLPLabel,
	doc any,
	url string,
) {
	switch label {
	case csaf.TLPLabelAmber, csaf.TLPLabelRed:
		// If the client has no authorization it shouldn't be able
		// to access TLP:AMBER or TLP:RED advisories
		p.badAmberRedPermissions.use()
		if !p.usedAuthorizedClient() {
			p.badAmberRedPermissions.error(
				"Advisory %s of TLP level %v is not access protected.",
				url, label)
		} else {
			res, err := p.unauthorizedClient().Get(url)
			if err != nil {
				p.badAmberRedPermissions.error(
					"Unexpected Error %v when trying to fetch: %s", err, url)
			} else if res.StatusCode == http.StatusOK {
				p.badAmberRedPermissions.error(
					"Advisory %s of TLP level %v is not properly access protected.",
					url, label)
			}
		}

	case csaf.TLPLabelWhite:
		// If we found a white labeled document we need to track it
		// to find out later if there was an unprotected way to access it.

		p.badWhitePermissions.use()
		// Being not able to extract the identifier from the document
		// indicates that the document is not valid. Should not happen
		// as the schema validation passed before.
		p.invalidAdvisories.use()
		if id, err := p.extractAdvisoryIdentifier(doc); err != nil {
			p.invalidAdvisories.error("Bad document %s: %v", url, err)
		} else if !lc.whiteAdvisories[id] {
			// Only do check if we haven't seen it as accessible before.

			if !p.usedAuthorizedClient() {
				// We already downloaded it without protection
				lc.whiteAdvisories[id] = true
			} else {
				// Need to try to re-download it unauthorized.
				if resp, err := p.unauthorizedClient().Get(url); err == nil {
					accessible := resp.StatusCode == http.StatusOK
					lc.whiteAdvisories[id] = accessible
					// If we are in a white rolie feed or in a dirlisting
					// directly warn if we cannot access it.
					// The cases of being in an amber or red feed are resolved.
					if !accessible &&
						(lc.feedLabel == "" || lc.feedLabel == csaf.TLPLabelWhite) {
						p.badWhitePermissions.warn(
							"Advisory %s of TLP level WHITE is access-protected.", url)
					}
				}
			}
		}
	}
}

// add registers a given url to a label.
func (lc *labelChecker) add(label csaf.TLPLabel, url string) {
	advs := lc.advisories[label]
	if advs == nil {
		advs = util.Set[string]{}
		lc.advisories[label] = advs
	}
	advs.Add(url)
}

// checkRank tests if a given advisory is contained by the
// the right feed color.
func (lc *labelChecker) checkRank(
	p *processor,
	label csaf.TLPLabel,
	url string,
) {
	// Only do this check when we are inside a ROLIE feed.
	if lc.feedLabel == "" {
		return
	}

	switch advisoryRank, feedRank := tlpLevel(label), tlpLevel(lc.feedLabel); {

	case advisoryRank < feedRank:
		if advisoryRank == 0 { // All kinds of 'UNLABELED'
			p.badROLIEFeed.info(
				"Found unlabeled advisory %q in feed %q.",
				url, lc.feedURL)
		} else {
			p.badROLIEFeed.warn(
				"Found advisory %q labled TLP:%s in feed %q (TLP:%s).",
				url, label,
				lc.feedURL, lc.feedLabel)
		}

	case advisoryRank > feedRank:
		// Must not happen, give error
		p.badROLIEFeed.error(
			"%s of TLP level %s must not be listed in feed %s of TLP level %s",
			url, label, lc.feedURL, lc.feedLabel)
	}
}

// defaults returns the value of the referencend pointer p
// if it is not nil, def otherwise.
func defaults[T any](p *T, def T) T {
	if p != nil {
		return *p
	}
	return def
}

// processROLIEFeeds goes through all ROLIE feeds and checks their
// integrity and completeness.
func (p *processor) processROLIEFeeds(feeds [][]csaf.Feed) error {

	base, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}
	base.Path = ""
	p.badROLIEFeed.use()

	advisories := map[*csaf.Feed][]csaf.AdvisoryFile{}

	// Phase 1: load all advisories urls.
	for _, fs := range feeds {
		for i := range fs {
			feed := &fs[i]
			if feed.URL == nil {
				continue
			}
			up, err := url.Parse(string(*feed.URL))
			if err != nil {
				p.badProviderMetadata.error("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}
			feedBase := misc.JoinURL(base, up)
			feedURL := feedBase.String()
			p.checkTLS(feedURL)

			advs, err := p.rolieFeedEntries(feedURL)
			if err != nil {
				if err != errContinue {
					return err
				}
				continue
			}
			advisories[feed] = advs
		}
	}

	// Phase 2: check for integrity.
	for _, fs := range feeds {
		for i := range fs {
			feed := &fs[i]
			if feed.URL == nil {
				continue
			}
			files := advisories[feed]
			if files == nil {
				continue
			}

			up, err := url.Parse(string(*feed.URL))
			if err != nil {
				p.badProviderMetadata.error("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}

			feedURL := misc.JoinURL(base, up)
			feedBase, err := util.BaseURL(feedURL)
			if err != nil {
				p.badProviderMetadata.error("Bad base path: %v", err)
				continue
			}

			label := defaults(feed.TLPLabel, csaf.TLPLabelUnlabeled)
			if err := p.categoryCheck(feedBase, label); err != nil {
				if err != errContinue {
					return err
				}
			}

			p.labelChecker.feedURL = feedURL.String()
			p.labelChecker.feedLabel = label

			// TODO: Issue a warning if we want check AMBER+ without an
			// authorizing client.

			if err := p.integrity(files, base.String(), rolieMask, p.badProviderMetadata.add); err != nil {
				if err != errContinue {
					return err
				}
			}
		}
	}

	// Phase 3: Check for completeness.

	hasSummary := util.Set[csaf.TLPLabel]{}

	var (
		hasUnlabeled = false
		hasWhite     = false
		hasGreen     = false
	)

	for _, fs := range feeds {
		for i := range fs {
			feed := &fs[i]
			if feed.URL == nil {
				continue
			}
			files := advisories[feed]
			if files == nil {
				continue
			}

			up, err := url.Parse(string(*feed.URL))
			if err != nil {
				p.badProviderMetadata.error("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}

			feedBase := misc.JoinURL(base, up)
			makeAbs := makeAbsolute(feedBase)
			label := defaults(feed.TLPLabel, csaf.TLPLabelUnlabeled)

			switch label {
			case csaf.TLPLabelUnlabeled:
				hasUnlabeled = true
			case csaf.TLPLabelWhite:
				hasWhite = true
			case csaf.TLPLabelGreen:
				hasGreen = true
			}

			reference := p.labelChecker.advisories[label]
			advisories := make(util.Set[string], len(reference))

			for _, adv := range files {
				u, err := url.Parse(adv.URL())
				if err != nil {
					p.badProviderMetadata.error(
						"Invalid URL %s in feed: %v.", *feed.URL, err)
					continue
				}
				advisories.Add(makeAbs(u).String())
			}
			if advisories.ContainsAll(reference) {
				hasSummary.Add(label)
			}
		}
	}

	if !hasWhite && !hasGreen && !hasUnlabeled {
		p.badROLIEFeed.error(
			"One ROLIE feed with a TLP:WHITE, TLP:GREEN or unlabeled tlp must exist, " +
				"but none were found.")
	}

	// Every TLP level with data should have at least on summary feed.
	for _, label := range []csaf.TLPLabel{
		csaf.TLPLabelUnlabeled,
		csaf.TLPLabelWhite,
		csaf.TLPLabelGreen,
		csaf.TLPLabelAmber,
		csaf.TLPLabelRed,
	} {
		if !hasSummary.Contains(label) && len(p.labelChecker.advisories[label]) > 0 {
			p.badROLIEFeed.warn(
				"ROLIE feed for TLP:%s has no accessible listed feed covering all advisories.",
				label)
		}
	}

	return nil
}

// categoryCheck checks for the existence of a feeds ROLIE category document and if it does,
// whether the category document contains distinguishing categories
func (p *processor) categoryCheck(folderURL string, label csaf.TLPLabel) error {
	labelname := strings.ToLower(string(label))
	urlrc := folderURL + "category-" + labelname + ".json"

	p.badROLIECategory.use()
	client := p.httpClient()
	res, err := client.Get(urlrc)
	if err != nil {
		p.badROLIECategory.error(
			"Cannot fetch rolie category document %s: %v", urlrc, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badROLIECategory.warn("Fetching %s failed. Status code %d (%s)",
			urlrc, res.StatusCode, res.Status)
		return errContinue
	}
	rolieCategory, err := func() (*csaf.ROLIECategoryDocument, error) {
		defer res.Body.Close()
		return csaf.LoadROLIECategoryDocument(res.Body)
	}()

	if err != nil {
		p.badROLIECategory.error(
			"Loading ROLIE category document %s failed: %v.", urlrc, err)
		return errContinue
	}
	if len(rolieCategory.Categories.Category) == 0 {
		p.badROLIECategory.warn(
			"No distinguishing categories in ROLIE category document: %s", urlrc)
	}
	return nil
}

// serviceCheck checks if a ROLIE service document exists and if it does,
// whether it contains all ROLIE feeds.
func (p *processor) serviceCheck(feeds [][]csaf.Feed) error {
	// service category document should be next to the pmd
	pmdURL, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}
	baseURL, err := util.BaseURL(pmdURL)
	if err != nil {
		return err
	}
	urls := baseURL + "service.json"

	// load service document
	p.badROLIEService.use()

	client := p.httpClient()
	res, err := client.Get(urls)
	if err != nil {
		p.badROLIEService.error(
			"Cannot fetch rolie service document %s: %v", urls, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badROLIEService.warn("Fetching %s failed. Status code %d (%s)",
			urls, res.StatusCode, res.Status)
		return errContinue
	}

	rolieService, err := func() (*csaf.ROLIEServiceDocument, error) {
		defer res.Body.Close()
		return csaf.LoadROLIEServiceDocument(res.Body)
	}()

	if err != nil {
		p.badROLIEService.error(
			"Loading ROLIE service document %s failed: %v.", urls, err)
		return errContinue
	}

	// Build lists of all feeds in feeds and in the Service Document
	var (
		sfeeds = util.Set[string]{}
		ffeeds = util.Set[string]{}
	)
	for _, col := range rolieService.Service.Workspace {
		for _, fd := range col.Collection {
			sfeeds.Add(fd.HRef)
		}
	}
	for _, r := range feeds {
		for _, s := range r {
			ffeeds.Add(string(*s.URL))
		}
	}

	// Check if ROLIE Service Document contains exactly all ROLIE feeds
	if m1 := sfeeds.Difference(ffeeds).Keys(); len(m1) != 0 {
		sort.Strings(m1)
		p.badROLIEService.error(
			"The ROLIE service document %s contains nonexistent feed entries: %v", urls, m1)
	}
	if m2 := ffeeds.Difference(sfeeds).Keys(); len(m2) != 0 {
		sort.Strings(m2)
		p.badROLIEService.error(
			"The ROLIE service document %s is missing feed entries: %v", urls, m2)
	}

	// TODO: Check conformity with RFC8322
	return nil
}

// extractAdvisoryIdentifier extracts document/publisher/namespace and
// document/tracking/id from advisory and stores it in an identifier.
func (p *processor) extractAdvisoryIdentifier(doc any) (identifier, error) {
	namespace, err := p.expr.Eval(`$.document.publisher.namespace`, doc)
	if err != nil {
		return identifier{}, err
	}

	idString, err := p.expr.Eval(`$.document.tracking.id`, doc)
	if err != nil {
		return identifier{}, err
	}

	ns, ok := namespace.(string)
	if !ok {
		return identifier{}, errors.New("cannot extract 'namespace'")
	}
	id, ok := idString.(string)
	if !ok {
		return identifier{}, errors.New("cannot extract 'id'")
	}

	return identifier{
		namespace: ns,
		id:        id,
	}, nil
}
