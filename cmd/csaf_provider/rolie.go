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
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

// mergeCategories merges the given categories into the old ones.
func (c *controller) mergeCategories(
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
) error {
	// Load the feed
	ts := string(t)
	feedName := "csaf-feed-tlp-" + ts + ".json"

	feed := filepath.Join(folder, feedName)
	rolie, err := loadROLIEFeed(feed)
	if err != nil {
		return err
	}

	feedURL := csaf.JSONURL(
		c.cfg.CanonicalURLPrefix +
			"/.well-known/csaf/" + ts + "/" + feedName)

	tlpLabel := csaf.TLPLabel(strings.ToUpper(ts))

	// Create new if does not exists.
	if rolie == nil {
		links := []csaf.Link{{
			Rel:  "self",
			HRef: string(feedURL),
		}}
		// If we have a service document we need to link it.
		if c.cfg.ServiceDocument {
			links = append(links, csaf.Link{
				Rel:  "service",
				HRef: c.cfg.CanonicalURLPrefix + "/.well-known/csaf/service.json",
			})
		}
		rolie = &csaf.ROLIEFeed{
			Feed: csaf.FeedData{
				ID:    "csaf-feed-tlp-" + ts,
				Title: "CSAF feed (TLP:" + string(tlpLabel) + ")",
				Link:  links,
				Category: []csaf.ROLIECategory{{
					Scheme: "urn:ietf:params:rolie:category:information-type",
					Term:   "csaf",
				}},
				Entry: []*csaf.Entry{},
			},
		}
	}

	rolie.Feed.Updated = csaf.TimeStamp(time.Now().UTC())

	year := strconv.Itoa(ex.InitialReleaseDate.Year())

	csafURL := c.cfg.CanonicalURLPrefix +
		"/.well-known/csaf/" + ts + "/" + year + "/" + newCSAF

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
	e.Format = csaf.Format{
		Schema:  "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json",
		Version: "2.0",
	}
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
