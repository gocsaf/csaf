// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

type SummaryPath struct {
	Filename string
	Summary  csaf.AdvisorySummary
}

func updateIndex(dir string, summaries []SummaryPath) error {
	index := filepath.Join(dir, "index.txt")

	lines, err := func() ([]string, error) {
		paths := []string{}
		f, err := os.Open(index)
		if err != nil {
			if os.IsNotExist(err) {
				for _, summary := range summaries {
					paths = append(paths, summary.Filename)
				}
				return paths, nil
			}
			return nil, err
		}
		defer f.Close()
		var lines []string
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			// stop scanning when we found it.
			if line := scanner.Text(); !slices.Contains(lines, line) {
				lines = append(lines, line)
			} else {
				if index, found := slices.BinarySearch(paths, line); found {
					slices.Delete(paths, index, index+1)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return append(lines, paths...), nil
	}()
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return nil
	}
	// Create new to break hard link.
	f, err := os.Create(index)
	if err != nil {
		return err
	}
	slices.Sort(lines)
	out := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(out, line)
	}
	if err := out.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func updateChanges(dir string, summaries []SummaryPath) error {
	type change struct {
		time time.Time
		path string
	}

	const (
		pathColumn = 0
		timeColumn = 1
	)

	changes := filepath.Join(dir, "changes.csv")

	chs, err := func() ([]change, error) {
		f, err := os.Open(changes)
		if err != nil {
			if os.IsNotExist(err) {
				chs := []change{}
				for _, summary := range summaries {
					chs = append(chs, change{summary.Summary.CurrentReleaseDate, summary.Filename})
				}
				return chs, nil
			}
			return nil, err
		}
		defer f.Close()
		var chs []change
		r := csv.NewReader(f)
		r.FieldsPerRecord = 2
		r.ReuseRecord = true
		replaced := false

		paths := []string{}
		for _, summary := range summaries {
			paths = append(paths, summary.Filename)
		}

		for {
			record, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			// Check if new is already in.
			if index, found := slices.BinarySearchFunc(summaries, SummaryPath{Filename: record[pathColumn]}, func(a, b SummaryPath) int {
				return strings.Compare(a.Filename, b.Filename)
			}); found {
				summaryEntry := summaries[index]
				releaseDate := summaryEntry.Summary.CurrentReleaseDate
				// Identical -> no change at all.
				if record[timeColumn] == releaseDate.Format(dateFormat) {
					return nil, nil
				}
				// replace old entry
				replaced = true
				chs = append(chs, change{releaseDate, summaryEntry.Filename})
				continue
			}
			t, err := time.Parse(dateFormat, record[timeColumn])
			if err != nil {
				return nil, err
			}
			chs = append(chs, change{t, record[pathColumn]})
		}
		if !replaced {
			for _, s := range summaries {
				chs = append(chs, change{s.Summary.CurrentReleaseDate, s.Filename})
			}
		}
		return chs, nil
	}()

	if err != nil {
		return err
	}
	if len(chs) == 0 {
		return nil
	}
	// Sort descending
	slices.SortFunc(chs, func(a, b change) int {
		return b.time.Compare(a.time)
	})
	// Create new to break hard link.
	o, err := os.Create(changes)
	if err != nil {
		return err
	}
	c := util.NewFullyQuotedCSWWriter(o)
	record := make([]string, 2)
	for _, ch := range chs {
		record[timeColumn] = ch.time.Format(dateFormat)
		record[pathColumn] = ch.path
		if err := c.Write(record); err != nil {
			o.Close()
			return err
		}
	}
	c.Flush()
	err1 := c.Error()
	err2 := o.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func updateIndices(dir string, summaries []SummaryPath) error {
	if err := updateIndex(dir, summaries); err != nil {
		return err
	}

	return updateChanges(dir, summaries)
}
