// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

func (w *worker) writeCSV(label string, summaries []summary) error {

	// Do not sort in-place.
	ss := make([]summary, len(summaries))
	copy(ss, summaries)

	sort.SliceStable(ss, func(i, j int) bool {
		return ss[i].summary.CurrentReleaseDate.After(
			ss[j].summary.CurrentReleaseDate)
	})

	fname := filepath.Join(w.dir, label, "changes.csv")
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	out := csv.NewWriter(f)

	record := make([]string, 2)

	for i := range ss {
		s := &ss[i]
		record[0] =
			s.summary.CurrentReleaseDate.Format(time.RFC3339)
		record[1] =
			strconv.Itoa(s.summary.InitialReleaseDate.Year()) + "/" + s.filename
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

	fname := filepath.Join(w.dir, label, "index.txt")
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

func (w *worker) writeROLIE(label string, summaries []summary) error {

	fname := "csaf-feed-tlp-" + strings.ToLower(label) + ".json"

	feedURL := w.cfg.Domain + "/.well-known/csaf-aggregator/" +
		w.provider.Name + "/" + fname

	entries := make([]*csaf.Entry, len(summaries))

	format := csaf.Format{
		Schema:  "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json",
		Version: "2.0",
	}

	for i := range summaries {
		s := &summaries[i]

		csafURL := w.cfg.Domain + "./well-known/csaf-aggregator/" +
			w.provider.Name + "/" + label + "/" +
			strconv.Itoa(s.summary.InitialReleaseDate.Year()) + "/" +
			s.filename

		entries[i] = &csaf.Entry{
			ID:        s.summary.ID,
			Titel:     s.summary.Title,
			Published: csaf.TimeStamp(s.summary.InitialReleaseDate),
			Updated:   csaf.TimeStamp(s.summary.CurrentReleaseDate),
			Link: []csaf.Link{{
				Rel:  "self",
				HRef: csafURL,
			}},
			Format: format,
			Content: csaf.Content{
				Type: "application/json",
				Src:  csafURL,
			},
		}
		if s.summary.Summary != "" {
			entries[i].Summary = &csaf.Summary{
				Content: s.summary.Summary,
			}
		}
	}

	rolie := &csaf.ROLIEFeed{
		Feed: csaf.FeedData{
			ID:    "csaf-feed-tlp-" + strings.ToLower(label),
			Title: "CSAF feed (TLP:" + strings.ToUpper(label) + ")",
			Link: []csaf.Link{{
				Rel:  "rel",
				HRef: feedURL,
			}},
			Updated: csaf.TimeStamp(time.Now()),
			Entry:   entries,
		},
	}

	// Sort by descending updated order.
	rolie.SortEntriesByUpdated()

	path := filepath.Join(w.dir, fname)
	return util.WriteToFile(path, rolie)
}

func (w *worker) writeIndices() error {

	if len(w.summaries) == 0 || w.dir == "" {
		return nil
	}

	for label, summaries := range w.summaries {
		log.Printf("%s: %d\n", label, len(summaries))
		if err := w.writeCSV(label, summaries); err != nil {
			return err
		}
		if err := w.writeIndex(label, summaries); err != nil {
			return err
		}
		if err := w.writeROLIE(label, summaries); err != nil {
			return err
		}
	}

	return nil
}