// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/csaf/provider"
	"github.com/gocsaf/csaf/v3/util"
)

// rolieFormats are the formats of ROLIE entries per CSAF version.
var rolieFormats = map[string]csaf.Format{
	csafVersion20: {
		Schema:  "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json",
		Version: csafVersion20,
	},
	csafVersion21: {
		Schema:  "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json",
		Version: csafVersion21,
	},
}

// mergeCategories merges the given categories into the old ones.
func mergeCategories(
	folder string,
	t tlp,
	categories []string,
) error {
	ts := string(t)
	catName := "category-" + ts + ".json"
	catPath := filepath.Join(folder, catName)

	catDoc, err := loadCategoryDocument(catPath)
	if err != nil {
		return err
	}

	var changed bool

	if catDoc == nil {
		catDoc = csaf.NewROLIECategoryDocument(categories...)
		changed = true
	} else {
		changed = catDoc.Merge(categories...)
	}

	if changed {
		if err := util.WriteToFile(catPath, catDoc); err != nil {
			return err
		}
	}
	return nil
}

// loadROLIEFeed loads a ROLIE feed from file if its exists.
// Returns nil if the file does not exists.
func loadCategoryDocument(path string) (*csaf.ROLIECategoryDocument, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return csaf.LoadROLIECategoryDocument(f)
}

// extendROLIE adds a new entry to the ROLIE feed for a given advisory.
func (c *controller) extendROLIE(
	folder string,
	newCSAF string,
	t tlp,
	ex *csaf.AdvisorySummary,
	pmd *provider.Provider,
	vtr *versionTree,
) error {
	// Load the feed
	feed := filepath.Join(folder, feedName(t))
	rolie, err := loadROLIEFeed(feed)
	if err != nil {
		return err
	}

	feedURL := vtr.feedURL(t)

	// Create new if does not exists.
	if rolie == nil {
		links := []csaf.Link{{
			Rel:  "self",
			HRef: feedURL,
		}}
		// If we have a service document we need to link it.
		if vtr.cfg.ServiceDocument {
			links = append(links, csaf.Link{
				Rel:  "service",
				HRef: vtr.url("service.json"),
			})
		}
		rolie = &csaf.ROLIEFeed{
			Feed: csaf.FeedData{
				ID:    "csaf-feed-tlp-" + string(t),
				Title: "CSAF feed (TLP:" + t.label() + ")",
				Link:  links,
				Category: []csaf.ROLIECategory{{
					Scheme: "urn:ietf:params:rolie:category:information-type",
					Term:   "csaf",
				}},
				Entry: []*csaf.Entry{},
			},
		}
	}

	updated := time.Now().UTC()
	rolie.Feed.Updated = csaf.TimeStamp(updated)

	year := strconv.Itoa(ex.InitialReleaseDate.Year())

	csafURL := vtr.url(string(t), year, newCSAF)

	e := rolie.EntryByID(ex.ID)
	if e == nil {
		e = &csaf.Entry{ID: ex.ID}
		rolie.Feed.Entry = append(rolie.Feed.Entry, e)
	}

	e.Titel = ex.Title
	e.Published = csaf.TimeStamp(ex.InitialReleaseDate)
	e.Updated = csaf.TimeStamp(ex.CurrentReleaseDate)
	e.Link = []csaf.Link{
		{Rel: "self", HRef: csafURL},
		{Rel: "hash", HRef: csafURL + ".sha256"},
		{Rel: "hash", HRef: csafURL + ".sha512"},
		{Rel: "signature", HRef: csafURL + ".asc"},
	}
	e.Format = rolieFormats[vtr.version]
	e.Content = csaf.Content{
		Type: "application/json",
		Src:  csafURL,
	}
	if ex.Summary != "" {
		e.Summary = &csaf.Summary{Content: ex.Summary}
	} else {
		e.Summary = nil
	}

	// Sort by descending updated order.
	rolie.SortEntriesByUpdated()

	if err := setLastUpdated(pmd, feedURL, timestamp(updated)); err != nil {
		return err
	}

	// Store the feed
	return util.WriteToFile(feed, rolie)
}

// loadROLIEFeed loads a ROLIE feed from file if its exists.
// Returns nil if the file does not exists.
func loadROLIEFeed(feed string) (*csaf.ROLIEFeed, error) {
	f, err := os.Open(feed)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return csaf.LoadROLIEFeed(f)
}
