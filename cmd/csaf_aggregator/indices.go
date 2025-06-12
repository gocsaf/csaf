// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

const (
	// interimsCSV is the name of the file to store the URLs
	// of the interim advisories.
	interimsCSV = "interims.csv"

	// changesCSV is the name of the file to store the
	// the paths to the advisories sorted in descending order
	// of the release date along with the release date.
	changesCSV = "changes.csv"

	// indexTXT is the name of the file to store the
	// the paths of the advisories.
	indexTXT = "index.txt"
)

func (w *worker) writeInterims(label string, summaries []summary) error {

	// Filter out the interims.
	var ss []summary
	for _, s := range summaries {
		if s.summary.Status == "interim" {
			ss = append(ss, s)
		}
	}

	// No interims -> nothing to write
	if len(ss) == 0 {
		return nil
	}

	sort.SliceStable(ss, func(i, j int) bool {
		return ss[i].summary.CurrentReleaseDate.After(
			ss[j].summary.CurrentReleaseDate)
	})

	fname := filepath.Join(w.dir, label, interimsCSV)
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	out := csv.NewWriter(f)

	record := make([]string, 3)

	for i := range ss {
		s := &ss[i]
		record[0] =
			s.summary.CurrentReleaseDate.Format(time.RFC3339)
		record[1] =
			strconv.Itoa(s.summary.InitialReleaseDate.Year()) + "/" + s.filename
		record[2] = s.url
		if err := out.Write(record); err != nil {
			f.Close()
			return err
		}
	}
	out.Flush()
	err1 := out.Error()
	err2 := f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (w *worker) writeCSV(label string, summaries []summary) error {

	fname := filepath.Join(w.dir, label, changesCSV)

	// If we don't have any entries remove existing file.
	if len(summaries) == 0 {
		// Does it really exist?
		if err := os.RemoveAll(fname); err != nil {
			return fmt.Errorf("unable to remove %q: %w", fname, err)
		}
		return nil
	}

	f, err := os.Create(fname)
	if err != nil {
		return err
	}

	// Do not sort in-place.
	ss := make([]summary, len(summaries))
	copy(ss, summaries)

	sort.SliceStable(ss, func(i, j int) bool {
		return ss[i].summary.CurrentReleaseDate.After(
			ss[j].summary.CurrentReleaseDate)
	})

	out := util.NewFullyQuotedCSWWriter(f)

	record := make([]string, 2)

	const (
		pathColumn = 0
		timeColumn = 1
	)

	for i := range ss {
		s := &ss[i]
		record[pathColumn] =
			strconv.Itoa(s.summary.InitialReleaseDate.Year()) + "/" + s.filename
		record[timeColumn] =
			s.summary.CurrentReleaseDate.Format(time.RFC3339)
		if err := out.Write(record); err != nil {
			f.Close()
			return err
		}
	}
	out.Flush()
	err1 := out.Error()
	err2 := f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (w *worker) writeIndex(label string, summaries []summary) error {

	fname := filepath.Join(w.dir, label, indexTXT)

	// If we don't have any entries remove existing file.
	if len(summaries) == 0 {
		// Does it really exist?
		if err := os.RemoveAll(fname); err != nil {
			return fmt.Errorf("unable to remove %q: %w", fname, err)
		}
		return nil
	}

	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	out := bufio.NewWriter(f)
	for i := range summaries {
		s := &summaries[i]
		fmt.Fprintf(
			out, "%d/%s\n",
			s.summary.InitialReleaseDate.Year(),
			s.filename)
	}
	err1 := out.Flush()
	err2 := f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (w *worker) writeROLIENoSummaries(label string) error {

	labelFolder := strings.ToLower(label)

	fname := "csaf-feed-tlp-" + labelFolder + ".json"

	feedURL, err := w.getProviderBaseURL()
	if err != nil {
		return err
	}
	feedURL = feedURL.JoinPath(labelFolder, fname)

	links := []csaf.Link{{
		Rel:  "self",
		HRef: feedURL.String(),
	}}

	if w.provider.serviceDocument(w.processor.cfg) {
		serviceURL, err := w.getProviderBaseURL()
		if err != nil {
			return err
		}
		serviceURL = serviceURL.JoinPath("service.json")
		links = append(links, csaf.Link{
			Rel:  "service",
			HRef: serviceURL.String(),
		})
	}

	rolie := &csaf.ROLIEFeed{
		Feed: csaf.FeedData{
			ID:    "csaf-feed-tlp-" + strings.ToLower(label),
			Title: "CSAF feed (TLP:" + strings.ToUpper(label) + ")",
			Link:  links,
			Category: []csaf.ROLIECategory{{
				Scheme: "urn:ietf:params:rolie:category:information-type",
				Term:   "csaf",
			}},
			Updated: csaf.TimeStamp(time.Now().UTC()),
			Entry:   []*csaf.Entry{},
		},
	}

	path := filepath.Join(w.dir, labelFolder, fname)
	return util.WriteToFile(path, rolie)
}

func (w *worker) writeROLIE(label string, summaries []summary) error {

	labelFolder := strings.ToLower(label)

	fname := "csaf-feed-tlp-" + labelFolder + ".json"

	feedURL, err := w.getProviderBaseURL()
	if err != nil {
		return err
	}
	feedURL = feedURL.JoinPath(labelFolder, fname)

	entries := make([]*csaf.Entry, len(summaries))

	format := csaf.Format{
		Schema:  "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json",
		Version: "2.0",
	}

	for i := range summaries {
		s := &summaries[i]

		csafURL, err := w.getProviderBaseURL()
		if err != nil {
			return err
		}
		csafURLString := csafURL.JoinPath(label,
			strconv.Itoa(s.summary.InitialReleaseDate.Year()),
			s.filename).String()

		entries[i] = &csaf.Entry{
			ID:        s.summary.ID,
			Titel:     s.summary.Title,
			Published: csaf.TimeStamp(s.summary.InitialReleaseDate),
			Updated:   csaf.TimeStamp(s.summary.CurrentReleaseDate),
			Link: []csaf.Link{
				{Rel: "self", HRef: csafURLString},
				{Rel: "hash", HRef: csafURLString + ".sha256"},
				{Rel: "hash", HRef: csafURLString + ".sha512"},
				{Rel: "signature", HRef: csafURLString + ".asc"},
			},
			Format: format,
			Content: csaf.Content{
				Type: "application/json",
				Src:  csafURLString,
			},
		}
		if s.summary.Summary != "" {
			entries[i].Summary = &csaf.Summary{
				Content: s.summary.Summary,
			}
		}
	}

	links := []csaf.Link{{
		Rel:  "self",
		HRef: feedURL.String(),
	}}

	if w.provider.serviceDocument(w.processor.cfg) {
		serviceURL, err := w.getProviderBaseURL()
		if err != nil {
			return err
		}
		serviceURL = serviceURL.JoinPath("service.json")
		links = append(links, csaf.Link{
			Rel:  "service",
			HRef: serviceURL.String(),
		})
	}

	rolie := &csaf.ROLIEFeed{
		Feed: csaf.FeedData{
			ID:    "csaf-feed-tlp-" + strings.ToLower(label),
			Title: "CSAF feed (TLP:" + strings.ToUpper(label) + ")",
			Link:  links,
			Category: []csaf.ROLIECategory{{
				Scheme: "urn:ietf:params:rolie:category:information-type",
				Term:   "csaf",
			}},
			Updated: csaf.TimeStamp(time.Now().UTC()),
			Entry:   entries,
		},
	}

	// Sort by descending updated order.
	rolie.SortEntriesByUpdated()

	path := filepath.Join(w.dir, labelFolder, fname)
	return util.WriteToFile(path, rolie)
}

func (w *worker) writeCategories(label string) error {
	categories := w.categories[label]
	if len(categories) == 0 {
		return nil
	}
	cats := make([]string, len(categories))
	var i int
	for cat := range categories {
		cats[i] = cat
		i++
	}
	rcd := csaf.NewROLIECategoryDocument(cats...)

	labelFolder := strings.ToLower(label)
	fname := "category-" + labelFolder + ".json"
	path := filepath.Join(w.dir, labelFolder, fname)
	return util.WriteToFile(path, rcd)
}

// writeService writes a service.json document if it is configured.
func (w *worker) writeService() error {

	if !w.provider.serviceDocument(w.processor.cfg) {
		return nil
	}
	labels := make([]string, len(w.summaries))
	var i int
	for label := range w.summaries {
		labels[i] = strings.ToLower(label)
		i++
	}
	sort.Strings(labels)

	categories := csaf.ROLIEServiceWorkspaceCollectionCategories{
		Category: []csaf.ROLIEServiceWorkspaceCollectionCategoriesCategory{{
			Scheme: "urn:ietf:params:rolie:category:information-type",
			Term:   "csaf",
		}},
	}

	var collections []csaf.ROLIEServiceWorkspaceCollection

	for _, ts := range labels {
		feedName := "csaf-feed-tlp-" + ts + ".json"

		hrefURL, err := w.getProviderBaseURL()
		if err != nil {
			return err
		}
		hrefURL = hrefURL.JoinPath(ts, feedName)

		collection := csaf.ROLIEServiceWorkspaceCollection{
			Title:      "CSAF feed (TLP:" + strings.ToUpper(ts) + ")",
			HRef:       hrefURL.String(),
			Categories: categories,
		}
		collections = append(collections, collection)
	}

	rsd := &csaf.ROLIEServiceDocument{
		Service: csaf.ROLIEService{
			Workspace: []csaf.ROLIEServiceWorkspace{{
				Title:      "CSAF feeds",
				Collection: collections,
			}},
		},
	}

	path := filepath.Join(w.dir, "service.json")
	return util.WriteToFile(path, rsd)
}

func (w *worker) writeIndices() error {

	if len(w.summaries) == 0 || w.dir == "" {
		w.writeROLIENoSummaries("undefined")
		return nil
	}

	for label, summaries := range w.summaries {
		w.log.Debug("Writing indices", "label", label, "summaries.num", len(summaries))
		if err := w.writeInterims(label, summaries); err != nil {
			return err
		}
		// Only write index.txt and changes.csv if configured.
		if w.provider.writeIndices(w.processor.cfg) {
			if err := w.writeCSV(label, summaries); err != nil {
				return err
			}
			if err := w.writeIndex(label, summaries); err != nil {
				return err
			}
		}
		if err := w.writeROLIE(label, summaries); err != nil {
			return err
		}
		if err := w.writeCategories(label); err != nil {
			return err
		}
	}

	return w.writeService()
}
