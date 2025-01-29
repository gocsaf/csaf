// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package csaf

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/util"
)

// AdvisoryFile constructs the urls of a remote file.
type AdvisoryFile interface {
	slog.LogValuer
	URL() string
	SHA256URL() string
	SHA512URL() string
	SignURL() string
	IsDirectory() bool
}

// PlainAdvisoryFile contains all relevant urls of a remote file.
type PlainAdvisoryFile struct {
	Path   string
	SHA256 string
	SHA512 string
	Sign   string
}

// URL returns the URL of this advisory.
func (paf PlainAdvisoryFile) URL() string { return paf.Path }

// SHA256URL returns the URL of SHA256 hash file of this advisory.
func (paf PlainAdvisoryFile) SHA256URL() string { return paf.SHA256 }

// SHA512URL returns the URL of SHA512 hash file of this advisory.
func (paf PlainAdvisoryFile) SHA512URL() string { return paf.SHA512 }

// SignURL returns the URL of signature file of this advisory.
func (paf PlainAdvisoryFile) SignURL() string { return paf.Sign }

// IsDirectory returns true, if was fetched via directory feeds.
func (paf PlainAdvisoryFile) IsDirectory() bool { return false }

// LogValue implements [slog.LogValuer]
func (paf PlainAdvisoryFile) LogValue() slog.Value {
	return slog.GroupValue(slog.String("url", paf.URL()))
}

// DirectoryAdvisoryFile only contains the base file path.
// The hash and signature files are directly constructed by extending
// the file name.
type DirectoryAdvisoryFile struct {
	Path string
}

// URL returns the URL of this advisory.
func (daf DirectoryAdvisoryFile) URL() string { return daf.Path }

// SHA256URL returns the URL of SHA256 hash file of this advisory.
func (daf DirectoryAdvisoryFile) SHA256URL() string { return daf.Path + ".sha256" }

// SHA512URL returns the URL of SHA512 hash file of this advisory.
func (daf DirectoryAdvisoryFile) SHA512URL() string { return daf.Path + ".sha512" }

// SignURL returns the URL of signature file of this advisory.
func (daf DirectoryAdvisoryFile) SignURL() string { return daf.Path + ".asc" }

// IsDirectory returns true, if was fetched via directory feeds.
func (daf DirectoryAdvisoryFile) IsDirectory() bool { return true }

// LogValue implements [slog.LogValuer]
func (daf DirectoryAdvisoryFile) LogValue() slog.Value {
	return slog.GroupValue(slog.String("url", daf.URL()))
}

// AdvisoryFileProcessor implements the extraction of
// advisory file names from a given provider metadata.
type AdvisoryFileProcessor struct {
	AgeAccept func(time.Time) bool
	Log       func(format string, args ...any)
	client    util.Client
	expr      *util.PathEval
	doc       any
	base      *url.URL
}

// NewAdvisoryFileProcessor constructs a filename extractor
// for a given metadata document.
func NewAdvisoryFileProcessor(
	client util.Client,
	expr *util.PathEval,
	doc any,
	base *url.URL,
) *AdvisoryFileProcessor {
	return &AdvisoryFileProcessor{
		client: client,
		expr:   expr,
		doc:    doc,
		base:   base,
	}
}

// empty checks if list of strings contains at least one none empty string.
func empty(arr []string) bool {
	for _, s := range arr {
		if s != "" {
			return false
		}
	}
	return true
}

// Process extracts the advisory filenames and passes them with
// the corresponding label to fn.
func (afp *AdvisoryFileProcessor) Process(
	fn func(TLPLabel, []AdvisoryFile) error,
) error {
	lg := afp.Log
	if lg == nil {
		lg = func(format string, args ...any) {
			log.Printf("AdvisoryFileProcessor.Process: "+format, args...)
		}
	}

	// Check if we have ROLIE feeds.
	rolie, err := afp.expr.Eval(
		"$.distributions[*].rolie.feeds", afp.doc)
	if err != nil {
		lg("rolie check failed: %v\n", err)
		return err
	}

	fs, hasRolie := rolie.([]any)
	hasRolie = hasRolie && len(fs) > 0

	if hasRolie {
		var feeds [][]Feed
		if err := util.ReMarshalJSON(&feeds, rolie); err != nil {
			return err
		}
		lg("Found %d ROLIE feed(s).\n", len(feeds))

		for _, feed := range feeds {
			if err := afp.processROLIE(feed, fn); err != nil {
				return err
			}
		}
	} else {
		// No rolie feeds -> try to load files from index.txt

		directoryURLs, err := afp.expr.Eval(
			"$.distributions[*].directory_url", afp.doc)

		var dirURLs []string

		if err != nil {
			lg("extracting directory URLs failed: %v\n", err)
		} else {
			var ok bool
			dirURLs, ok = util.AsStrings(directoryURLs)
			if !ok {
				lg("directory_urls are not strings.\n")
			}
		}

		// Not found -> fall back to PMD url
		if empty(dirURLs) {
			baseURL, err := util.BaseURL(afp.base)
			if err != nil {
				return err
			}
			dirURLs = []string{baseURL}
		}

		for _, base := range dirURLs {
			if base == "" {
				continue
			}

			// Use changes.csv to be able to filter by age.
			files, err := afp.loadChanges(base, lg)
			if err != nil {
				return err
			}
			// XXX: Is treating as white okay? better look into the advisories?
			if err := fn(TLPLabelWhite, files); err != nil {
				return err
			}
		}
	} // TODO: else scan directories?
	return nil
}

// loadChanges loads baseURL/changes.csv and returns a list of files
// prefixed by baseURL/.
func (afp *AdvisoryFileProcessor) loadChanges(
	baseURL string,
	lg func(string, ...any),
) ([]AdvisoryFile, error) {

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	changesURL := base.JoinPath("changes.csv").String()

	resp, err := afp.client.Get(changesURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s failed. Status code %d (%s)",
			changesURL, resp.StatusCode, resp.Status)
	}

	defer resp.Body.Close()
	var files []AdvisoryFile
	c := csv.NewReader(resp.Body)
	const (
		pathColumn = 0
		timeColumn = 1
	)
	for line := 1; ; line++ {
		r, err := c.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(r) < 2 {
			lg("%q has not enough columns in line %d", line)
			continue
		}
		t, err := time.Parse(time.RFC3339, r[timeColumn])
		if err != nil {
			lg("%q has an invalid time stamp in line %d: %v", changesURL, line, err)
			continue
		}
		// Apply date range filtering.
		if afp.AgeAccept != nil && !afp.AgeAccept(t) {
			continue
		}
		path := r[pathColumn]
		if _, err := url.Parse(path); err != nil {
			lg("%q contains an invalid URL %q in line %d", changesURL, path, line)
			continue
		}

		files = append(files,
			DirectoryAdvisoryFile{Path: base.JoinPath(path).String()})
	}
	return files, nil
}

func (afp *AdvisoryFileProcessor) processROLIE(
	labeledFeeds []Feed,
	fn func(TLPLabel, []AdvisoryFile) error,
) error {
	for i := range labeledFeeds {
		feed := &labeledFeeds[i]
		if feed.URL == nil {
			continue
		}
		up, err := url.Parse(string(*feed.URL))
		if err != nil {
			log.Printf("Invalid URL %s in feed: %v.", *feed.URL, err)
			continue
		}
		feedURL := afp.base.ResolveReference(up)
		log.Printf("Feed URL: %s\n", feedURL)

		fb, err := util.BaseURL(feedURL)
		if err != nil {
			log.Printf("error: Invalid feed base URL '%s': %v\n", fb, err)
			continue
		}
		feedBaseURL, err := url.Parse(fb)
		if err != nil {
			log.Printf("error: Cannot parse feed base URL '%s': %v\n", fb, err)
			continue
		}

		res, err := afp.client.Get(feedURL.String())
		if err != nil {
			log.Printf("error: Cannot get feed '%s'\n", err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			log.Printf("error: Fetching %s failed. Status code %d (%s)",
				feedURL, res.StatusCode, res.Status)
			continue
		}
		rfeed, err := func() (*ROLIEFeed, error) {
			defer res.Body.Close()
			return LoadROLIEFeed(res.Body)
		}()
		if err != nil {
			log.Printf("Loading ROLIE feed failed: %v.", err)
			continue
		}

		var files []AdvisoryFile

		resolve := func(u string) string {
			if u == "" {
				return ""
			}
			p, err := url.Parse(u)
			if err != nil {
				log.Printf("error: Invalid URL '%s': %v", u, err)
				return ""
			}
			return feedBaseURL.ResolveReference(p).String()
		}

		rfeed.Entries(func(entry *Entry) {
			// Filter if we have date checking.
			if afp.AgeAccept != nil {
				if t := time.Time(entry.Updated); !t.IsZero() && !afp.AgeAccept(t) {
					return
				}
			}

			var self, sha256, sha512, sign string

			for i := range entry.Link {
				link := &entry.Link[i]
				lower := strings.ToLower(link.HRef)
				switch link.Rel {
				case "self":
					self = resolve(link.HRef)
				case "signature":
					sign = resolve(link.HRef)
				case "hash":
					switch {
					case strings.HasSuffix(lower, ".sha256"):
						sha256 = resolve(link.HRef)
					case strings.HasSuffix(lower, ".sha512"):
						sha512 = resolve(link.HRef)
					}
				}
			}

			if self == "" {
				return
			}

			var file AdvisoryFile

			switch {
			case sha256 == "" && sha512 == "":
				slog.Error("No hash listed on ROLIE feed", "file", self)
				return
			case sign == "":
				slog.Error("No signature listed on ROLIE feed", "file", self)
				return
			default:
				file = PlainAdvisoryFile{self, sha256, sha512, sign}
			}

			files = append(files, file)
		})

		var label TLPLabel
		if feed.TLPLabel != nil {
			label = *feed.TLPLabel
		} else {
			label = "unknown"
		}

		if err := fn(label, files); err != nil {
			return err
		}
	}
	return nil
}
