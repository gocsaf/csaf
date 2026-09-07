// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package csaf

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

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

//	--- csaf_2.0/json_schema/provider_json_schema.json
//	+++ csaf_2.1/json_schema/provider.json
//		@@ -1,6 +1,6 @@
//		{
//		-  "$schema": "https://json-schema.org/draft/2020-12/schema",
//		-  "$id": "https://docs.oasis-open.org/csaf/csaf/v2.0/provider_json_schema.json",
//		+  "$schema": "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/meta.json",
//		+  "$id": "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/provider.json",
//		"title": "CSAF provider metadata",
//		"description": "Representation of metadata information of a CSAF provider as a JSON document.",
//		"type": "object",
//		@@ -17,7 +17,7 @@
//			"description": "Contains a URL of a provider-metadata.json.",
//			"type": "string",
//			"format": "uri",
//		-      "pattern": "/provider-metadata\\.json$"
//		+      "pattern": "\\/provider-metadata\\.json$"
//			},
//			"url_t": {
//			"title": "Generic URL type",
//		@@ -27,6 +27,7 @@
//			}
//		},
//		"required": [
//		+    "$schema",
//			"canonical_url",
//			"last_updated",
//			"list_on_CSAF_aggregators",
//		@@ -36,6 +37,15 @@
//			"role"
//		],
//		"properties": {
//		+    "$schema": {
//		+      "title": "JSON schema",
//		+      "description": "Contains the URL of the provider-metadata.json JSON schema which the document promises to be valid for.",
//		+      "type": "string",
//		+      "enum": [
//		+        "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/provider.json"
//		+      ],
//		+      "format": "uri"
//		+    },
//			"canonical_url": {
//			"title": "Canonical URL",
//			"description": "Contains the URL for this document.",
//		@@ -53,17 +63,34 @@
//				"type": "object",
//				"minProperties": 1,
//				"properties": {
//		-          "directory_url": {
//		-            "title": "Directory URL",
//		-            "description": "Contains the base url for the directory distribution.",
//		-            "$ref": "#/$defs/url_t"
//		+          "directory": {
//		+            "title": "Directory",
//		+            "description": "Contains all information for directory-based distribution.",
//		+            "type": "object",
//		+            "required": [
//		+              "tlp_label",
//		+              "url"
//		+            ],
//		+            "properties": {
//		+              "tlp_label": {
//		+                "title": "TLP label",
//		+                "description": "Provides the TLP label for the directory.",
//		+                "$ref": "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json#/properties/document/properties/distribution/properties/tlp/properties/label"
//		+              },
//		+              "url": {
//		+                "title": "Directory URL",
//		+                "description": "Contains the base url for the directory-based distribution.",
//		+                "$ref": "#/$defs/url_t"
//		+              }
//		+            },
//		+            "additionalProperties": false
//				},
//				"rolie": {
//					"title": "ROLIE",
//					"description": "Contains all information for ROLIE distribution.",
//					"type": "object",
//					"required": [
//		-                "feeds"
//		+              "feeds"
//					],
//					"properties": {
//					"categories": {
//		@@ -89,36 +116,37 @@
//						"description": "Contains information about the ROLIE feed.",
//						"type": "object",
//						"required": [
//		+                    "last_updated",
//							"tlp_label",
//							"url"
//						],
//						"properties": {
//		+                    "last_updated": {
//		+                      "title": "Last updated",
//		+                      "description": "Holds the date and time when the feed was last updated.",
//		+                      "type": "string",
//		+                      "format": "date-time"
//		+                    },
//							"summary": {
//							"title": "Summary of the feed",
//							"description": "Contains a summary of the feed.",
//							"type": "string",
//							"examples": [
//		-                        "All TLP:WHITE advisories of Example Company."
//		+                        "All TLP:CLEAR advisories of Example Company."
//							]
//							},
//							"tlp_label": {
//							"title": "TLP label",
//							"description": "Provides the TLP label for the feed.",
//		-                      "type": "string",
//		-                      "enum": [
//		-                        "UNLABELED",
//		-                        "WHITE",
//		-                        "GREEN",
//		-                        "AMBER",
//		-                        "RED"
//		-                      ]
//		+                      "$ref": "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json#/properties/document/properties/distribution/properties/tlp/properties/label"
//							},
//							"url": {
//							"title": "URL of the feed",
//							"description": "Contains the URL of the feed.",
//							"$ref": "#/$defs/json_url_t"
//							}
//		-                  }
//		+                  },
//		+                  "additionalProperties": false
//						}
//					},
//					"services": {
//		@@ -133,9 +161,11 @@
//						"$ref": "#/$defs/json_url_t"
//						}
//					}
//		-            }
//		+            },
//		+            "additionalProperties": false
//				}
//		-        }
//		+        },
//		+        "additionalProperties": false
//			}
//			},
//			"last_updated": {
//		@@ -150,12 +180,24 @@
//			"type": "boolean",
//			"default": true
//			},
//		+    "maintained_from": {
//		+      "title": "Maintained from",
//		+      "description": "Holds the date and time from when the distributions within this CSAF provider are in a maintained state.",
//		+      "type": "string",
//		+      "format": "date-time"
//		+    },
//		+    "maintained_until": {
//		+      "title": "Maintained until",
//		+      "description": "Holds the date and time until when the distributions within this CSAF provider are in a maintained state.",
//		+      "type": "string",
//		+      "format": "date-time"
//		+    },
//			"metadata_version": {
//			"title": "CSAF provider metadata version",
//			"description": "Gives the version of the CSAF provider metadata specification which the document was generated for.",
//			"type": "string",
//			"enum": [
//		-        "2.0"
//		+        "2.1"
//			]
//			},
//			"mirror_on_CSAF_aggregators": {
//		@@ -173,6 +215,7 @@
//				"description": "Contains all information about an OpenPGP key used to sign CSAF documents.",
//				"type": "object",
//				"required": [
//		+          "fingerprint",
//				"url"
//				],
//				"properties": {
//		@@ -188,13 +231,14 @@
//					"description": "Contains the URL where the key can be retrieved.",
//					"$ref": "#/$defs/url_t"
//				}
//		-        }
//		+        },
//		+        "additionalProperties": false
//			}
//			},
//			"publisher": {
//			"title": "Publisher",
//			"description": "Provides information about the publisher of the CSAF documents in this repository.",
//		-      "$ref": "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json#/properties/document/properties/publisher"
//		+      "$ref": "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json#/properties/document/properties/publisher"
//			},
//			"role": {
//			"title": "Role of the issuing party",
//		@@ -207,5 +251,6 @@
//				"csaf_trusted_provider"
//			]
//			}
//		-  }
//		+  },
//		+  "additionalProperties": false
//		}
//
// Sources:
// https://github.com/oasis-tcs/csaf/blob/master/csaf_2.0/json_schema/provider_json_schema.json
// https://github.com/oasis-tcs/csaf/blob/master/csaf_2.1/json_schema/provider.json
type AdvisoryFileProcessor struct {
	AgeAccept            func(time.Time) bool
	Log                  func(loglevel slog.Level, format string, args ...any)
	client               util.Client
	expr                 *util.PathEval
	doc                  any
	pmdURL               *url.URL
	StreamingROLIEParser bool
}

// NewAdvisoryFileProcessor constructs a filename extractor
// for a given metadata document.
func NewAdvisoryFileProcessor(
	client util.Client,
	expr *util.PathEval,
	doc any,
	pmdURL *url.URL,
) *AdvisoryFileProcessor {
	return &AdvisoryFileProcessor{
		client: client,
		expr:   expr,
		doc:    doc,
		pmdURL: pmdURL,
	}
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
	rolie, err := afp.expr.Eval(
		"$.distributions[*].rolie.feeds", afp.doc)
	if err != nil {
		lg(slog.LevelError, "rolie check failed", "err", err)
		return err
	}

	fs, hasRolie := rolie.([]any)
	hasRolie = hasRolie && len(fs) > 0

	if hasRolie {
		var feeds [][]ProviderDistributionsElemRolieFeedsElem
		if err := util.ReMarshalJSON(&feeds, rolie); err != nil {
			return err
		}
		lg(slog.LevelInfo, "Found ROLIE feed(s)", "length", len(feeds))

		for _, feed := range feeds {
			if err := afp.processROLIE(ctx, feed, fn); err != nil {
				return err
			}
		}
	} else {
		// No rolie feeds -> try to load files from index.txt

		directories, err := extractV21AdvisoryDirectories(afp.doc)
		if err != nil {
			lg(slog.LevelError, "extracting directories failed", "err", err)
			return err
		}

		// Not found -> fall back to PMD url
		if len(directories) == 0 {
			baseURL, err := util.BaseURL(afp.pmdURL)
			if err != nil {
				return err
			}
			directories = []advisoryDirectory{{
				url:      baseURL,
				tlpLabel: TLPLabelClear,
			}}
		}

		for _, directory := range directories {
			if directory.url == "" {
				continue
			}

			// Use changes.csv to be able to filter by age.
			files, err := afp.loadChanges(ctx, directory.url, lg)
			if err != nil {
				return err
			}
			if err := fn(directory.tlpLabel, files); err != nil {
				return err
			}
		}
	} // TODO: else scan directories?
	return nil
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
	labeledFeeds []ProviderDistributionsElemRolieFeedsElem,
	fn func(TLPLabel, []AdvisoryFile) error,
) error {
	for i := range labeledFeeds {
		feed := &labeledFeeds[i]
		if feed.URL == "" {
			continue
		}
		feedURL, err := url.Parse(string(feed.URL))
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
		case sha256 == "" && sha512 == "":
			slog.Error("No hash listed on ROLIE feed", "file", self)
			return
		case sign == "":
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
			case sha256 == "" && sha512 == "":
				slog.Error("No hash listed on ROLIE feed", "file", self)
				return
			case sign == "":
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
