// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package csaf

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf/provider"
	"github.com/gocsaf/csaf/v3/internal/misc"
	"github.com/gocsaf/csaf/v3/internal/models"
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
	AgeAccept            func(time.Time) bool
	Log                  func(loglevel slog.Level, format string, args ...any)
	client               util.Client
	pmd                  *provider.Provider
	pmdURL               *url.URL
	StreamingROLIEParser bool
}

// NewAdvisoryFileProcessor constructs a filename extractor
// for a given metadata document.
func NewAdvisoryFileProcessor(
	client util.Client,
	pmd *provider.Provider,
	pmdURL *url.URL,
) *AdvisoryFileProcessor {
	return &AdvisoryFileProcessor{
		client: client,
		pmd:    pmd,
		pmdURL: pmdURL,
	}
}

// advisoryDir holds URL and TLP label of a dir based distribution element
type advisoryDir struct {
	url   string
	label TLPLabel
}

// getAdvisoryDirs returns list of dir based distribution elements.
func getAdvisoryDirs(pmd *provider.Provider) []advisoryDir {
	var dirs []advisoryDir
	for i := range pmd.Distributions {
		dist := &pmd.Distributions[i]
		if u, _ := dist.DirectoryURL(); u != nil && *u != "" {
			// XXX: Is treating as white okay? better look into the advisories?
			dirs = append(dirs, advisoryDir{
				url:   string(*u),
				label: TLPLabelDefault(Version20),
			})
		}
		if dir, _ := dist.Directory(); dir != nil && dir.URL != "" {
			dirs = append(dirs, advisoryDir{
				url:   string(dir.URL),
				label: TLPLabel(dir.TLPLabel),
			})
		}
	}
	return dirs
}

// Process is a wrapper for ProcessWithContext function and supplements
// a required context.Background() as first parameter.
func (afp *AdvisoryFileProcessor) Process(
	fn func(TLPLabel, []AdvisoryFile) error,
) error {
	return afp.ProcessWithContext(context.Background(), fn)
}

// ProcessWithContext extracts the advisory filenames and passes them with
// the corresponding label to fn. This function is context aware and takes
// context.Context as first parameter.
func (afp *AdvisoryFileProcessor) ProcessWithContext(
	ctx context.Context,
	fn func(TLPLabel, []AdvisoryFile) error,
) error {
	lg := afp.Log
	if lg == nil {
		lg = func(loglevel slog.Level, format string, args ...any) {
			slog.Log(ctx, loglevel, "AdvisoryFileProcessor.Process: "+format, args...)
		}
	}

	// Check if we have ROLIE feeds.
	// if both present, prefer ROLIE
	var feeds [][]provider.ProviderDistributionsElemRolieFeedsElem
	for i := range afp.pmd.Distributions {
		if r := afp.pmd.Distributions[i].Rolie; r != nil && len(r.Feeds) > 0 {
			feeds = append(feeds, r.Feeds)
		}
	}

	if len(feeds) > 0 {
		lg(slog.LevelInfo, "Found ROLIE feed(s)", "length", len(feeds))

		for _, feed := range feeds {
			if err := afp.processROLIE(ctx, feed, fn); err != nil {
				return err
			}
		}
		return nil
	}

	// No rolie feeds -> try to load files from index.txt
	directories := getAdvisoryDirs(afp.pmd)

	// Not found -> fall back to PMD url
	if len(directories) == 0 {
		baseURL, err := util.BaseURL(afp.pmdURL)
		if err != nil {
			return err
		}
		directories = []advisoryDir{{
			url:   baseURL,
			label: TLPLabelDefault(SpecVersion(afp.pmd.MetadataVersion)),
		}}
	}

	for _, dir := range directories {
		var (
			files []AdvisoryFile
			err   error
		)
		if afp.AgeAccept == nil {
			files, err = afp.loadIndex(ctx, dir.url, lg)
		} else {
			files, err = afp.loadChanges(ctx, dir.url, lg)
		}
		if err != nil {
			return err
		}
		// XXX: Is treating as white okay? better look into the advisories?
		if err := fn(dir.label, files); err != nil {
			return err
		}
	}
	// TODO: else scan directories?
	return nil
}

// loadIndex loads baseURL/index.txt and returns a list of files
// prefixed by baseURL/.
func (afp *AdvisoryFileProcessor) loadIndex(
	ctx context.Context,
	baseURL string,
	lg func(slog.Level, string, ...any),
) ([]AdvisoryFile, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	indexURL := base.JoinPath("index.txt").String()

	var resp *http.Response
	if cwc, ok := afp.client.(util.ClientWithContext); ok {
		resp, err = cwc.GetWithContext(ctx, indexURL)
	} else {
		resp, err = afp.client.Get(indexURL)
	}
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s failed. Status code %d (%s)",
			indexURL, resp.StatusCode, resp.Status)
	}

	var files []AdvisoryFile
	scanner := bufio.NewScanner(resp.Body)
	for line := 1; scanner.Scan(); line++ {
		path := strings.TrimSpace(scanner.Text())
		if path == "" {
			continue
		}
		pathURL, err := url.Parse(path)
		if err != nil {
			lg(slog.LevelError, "Contains an invalid URL", "url", indexURL, "path", path, "line", line)
			continue
		}
		files = append(files,
			DirectoryAdvisoryFile{Path: misc.JoinURL(base, pathURL).String()})
	}
	return files, nil
}

// loadChanges loads baseURL/changes.csv and returns a list of files
// prefixed by baseURL/.
func (afp *AdvisoryFileProcessor) loadChanges(
	ctx context.Context,
	baseURL string,
	lg func(slog.Level, string, ...any),
) ([]AdvisoryFile, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	changesURL := base.JoinPath("changes.csv").String()

	var resp *http.Response
	if cwc, ok := afp.client.(util.ClientWithContext); ok {
		resp, err = cwc.GetWithContext(ctx, changesURL)
	} else {
		resp, err = afp.client.Get(changesURL)
	}
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s failed. Status code %d (%s)",
			changesURL, resp.StatusCode, resp.Status)
	}

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
			lg(slog.LevelError, "Not enough columns", "line", line)
			continue
		}
		t, err := time.Parse(time.RFC3339, r[timeColumn])
		if err != nil {
			lg(slog.LevelError, "Invalid time stamp in line", "url", changesURL, "line", line, "err", err)
			continue
		}
		// Apply date range filtering.
		if afp.AgeAccept != nil && !afp.AgeAccept(t) {
			continue
		}
		path := r[pathColumn]
		if _, err := url.Parse(path); err != nil {
			lg(slog.LevelError, "Contains an invalid URL", "url", changesURL, "path", path, "line", line)
			continue
		}

		pathURL, err := url.Parse(path)
		if err != nil {
			return nil, err
		}

		files = append(files,
			DirectoryAdvisoryFile{Path: misc.JoinURL(base, pathURL).String()})
	}
	return files, nil
}

func (afp *AdvisoryFileProcessor) processROLIE(
	ctx context.Context,
	labeledFeeds []provider.ProviderDistributionsElemRolieFeedsElem,
	fn func(TLPLabel, []AdvisoryFile) error,
) error {
	for i := range labeledFeeds {
		feed := &labeledFeeds[i]
		if feed.URL == "" {
			continue
		}
		feedURL, err := url.Parse(feed.URL)
		if err != nil {
			slog.Error("Invalid URL in feed", "feed", feed.URL, "err", err)
			continue
		}
		slog.Info("Got feed URL", "feed", feedURL)

		fb, err := util.BaseURL(feedURL)
		if err != nil {
			slog.Error("Invalid feed base URL", "url", fb, "err", err)
			continue
		}

		var res *http.Response
		if cwc, ok := afp.client.(util.ClientWithContext); ok {
			res, err = cwc.GetWithContext(ctx, feedURL.String())
		} else {
			res, err = afp.client.Get(feedURL.String())
		}
		if err != nil {
			slog.Error("Cannot get feed", "err", err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			slog.Error("Fetching failed",
				"url", feedURL, "status_code", res.StatusCode, "status", res.Status)
			res.Body.Close()
			continue
		}
		var files []AdvisoryFile
		if afp.StreamingROLIEParser {
			if err := afp.processROLIEStream(&files, res); err != nil {
				slog.Error("Streaming ROLIE feed failed", "err", err)
				continue
			}
		} else if err := afp.processROLIELegacy(&files, res); err != nil {
			slog.Error("Loading ROLIE feed failed", "err", err)
			continue
		}

		if err := fn(TLPLabel(feed.TLPLabel), files); err != nil {
			return err
		}
	}
	return nil
}

func (afp *AdvisoryFileProcessor) processROLIELegacy(files *[]AdvisoryFile, res *http.Response) error {
	rfeed, err := func() (*ROLIEFeed, error) {
		defer res.Body.Close()
		return LoadROLIEFeed(res.Body)
	}()
	if err != nil {
		return err
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
				self = afp.resolveURL(link.HRef)
			case "signature":
				sign = afp.resolveURL(link.HRef)
			case "hash":
				switch {
				case strings.HasSuffix(lower, ".sha256"):
					sha256 = afp.resolveURL(link.HRef)
				case strings.HasSuffix(lower, ".sha512"):
					sha512 = afp.resolveURL(link.HRef)
				}
			}
		}

		if self == "" {
			return
		}

		switch {
		case sha256 == "" && sha512 == "" && afp.pmd.Role == string(MetadataRoleTrustedProvider):
			slog.Error("No hash listed on ROLIE feed", "file", self)
			return
		case sign == "" && afp.pmd.Role == string(MetadataRoleTrustedProvider):
			slog.Error("No signature listed on ROLIE feed", "file", self)
			return
		default:
			*files = append(*files, PlainAdvisoryFile{self, sha256, sha512, sign})
		}
	})
	return nil
}

func (afp *AdvisoryFileProcessor) processROLIEStream(files *[]AdvisoryFile, res *http.Response) error {
	defer res.Body.Close()
	srp := models.StreamingROLIEParser{
		HandleEntry: func(sr *models.StreamingROLIEParser) {
			// Filter if we have date checking.
			if afp.AgeAccept != nil {
				if t := time.Time(sr.Updated); !t.IsZero() && !afp.AgeAccept(t) {
					return
				}
			}

			var self, sha256, sha512, sign string

			for i := range sr.Links {
				link := sr.Links[i]
				lower := strings.ToLower(link.HRef)
				switch link.Rel {
				case "self":
					self = afp.resolveURL(link.HRef)
				case "signature":
					sign = afp.resolveURL(link.HRef)
				case "hash":
					switch {
					case strings.HasSuffix(lower, ".sha256"):
						sha256 = afp.resolveURL(link.HRef)
					case strings.HasSuffix(lower, ".sha512"):
						sha512 = afp.resolveURL(link.HRef)
					}
				}
			}

			if self == "" {
				return
			}

			var file AdvisoryFile

			switch {
			case sha256 == "" && sha512 == "" && afp.pmd.Role == string(MetadataRoleTrustedProvider):
				slog.Error("No hash listed on ROLIE feed", "file", self)
				return
			case sign == "" && afp.pmd.Role == string(MetadataRoleTrustedProvider):
				slog.Error("No signature listed on ROLIE feed", "file", self)
				return
			default:
				file = PlainAdvisoryFile{self, sha256, sha512, sign}
			}

			*files = append(*files, file)
		},
	}
	return srp.Parse(res.Body)
}

func (afp *AdvisoryFileProcessor) resolveURL(u string) string {
	if u == "" {
		return ""
	}
	p, err := url.Parse(u)
	if err != nil {
		slog.Error("Invalid URL", "url", u, "err", err)
		return ""
	}
	return p.String()
}
