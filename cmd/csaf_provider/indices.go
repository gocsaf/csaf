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
	"sort"
	"time"

	"github.com/gocsaf/csaf/v3/util"
)

func updateIndex(dir, fname string) error {

	index := filepath.Join(dir, "index.txt")

	lines, err := func() ([]string, error) {
		f, err := os.Open(index)
		if err != nil {
			if os.IsNotExist(err) {
				return []string{fname}, nil
			}
			return nil, err
		}
		defer f.Close()
		var lines []string
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			// stop scanning when we found it.
			if line := scanner.Text(); line != fname {
				lines = append(lines, line)
			} else {
				return nil, nil
			}
		}
		return append(lines, fname), nil
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
	sort.Strings(lines)
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

func updateChanges(dir, fname string, releaseDate time.Time) error {

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
				return []change{{releaseDate, fname}}, nil
			}
			return nil, err
		}
		defer f.Close()
		var chs []change
		r := csv.NewReader(f)
		r.FieldsPerRecord = 2
		r.ReuseRecord = true
		replaced := false
		for {
			record, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			// Check if new is already in.
			if record[pathColumn] == fname {
				// Identical -> no change at all.
				if record[timeColumn] == releaseDate.Format(dateFormat) {
					return nil, nil
				}
				// replace old entry
				replaced = true
				chs = append(chs, change{releaseDate, fname})
				continue
			}
			t, err := time.Parse(dateFormat, record[timeColumn])
			if err != nil {
				return nil, err
			}
			chs = append(chs, change{t, record[pathColumn]})
		}
		if !replaced {
			chs = append(chs, change{releaseDate, fname})
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
	sort.Slice(chs, func(i, j int) bool {
		return chs[j].time.Before(chs[i].time)
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

func updateIndices(dir, fname string, releaseDate time.Time) error {

	if err := updateIndex(dir, fname); err != nil {
		return err
	}

	return updateChanges(dir, fname, releaseDate)
}
