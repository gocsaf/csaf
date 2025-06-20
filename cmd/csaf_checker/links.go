// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"github.com/gocsaf/csaf/v3/internal/misc"
	"io"
	"net/http"
	"net/url"

	"github.com/PuerkitoBio/goquery"

	"github.com/gocsaf/csaf/v3/util"
)

type (
	pageContent struct {
		err   error
		links util.Set[string]
	}
	pages map[string]*pageContent
)

func (pgs pages) listed(
	path string,
	pro *processor,
	badDirs util.Set[string],
) (bool, error) {
	pathURL, err := url.Parse(path)
	if err != nil {
		return false, err
	}

	base, err := util.BaseURL(pathURL)
	if err != nil {
		return false, err
	}

	content := pgs[base]
	if content != nil { // already loaded
		if content.err != nil {
			return false, nil
		}
		return content.links.Contains(path), nil
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return false, err
	}

	if badDirs.Contains(base) {
		return false, errContinue
	}

	// load page
	client := pro.httpClient()
	pro.checkTLS(base)
	res, err := client.Get(base)

	pro.badDirListings.use()

	if err != nil {
		pro.badDirListings.error("Fetching %s failed: %v", base, err)
		badDirs.Add(base)
		return false, errContinue
	}
	if res.StatusCode != http.StatusOK {
		pro.badDirListings.error("Fetching %s failed. Status code %d (%s)",
			base, res.StatusCode, res.Status)
		badDirs.Add(base)
		return false, errContinue
	}

	content = &pageContent{
		links: util.Set[string]{},
	}

	pgs[base] = content

	// Build link index for this page.

	if err := func() error {
		defer res.Body.Close()
		return linksOnPage(res.Body, func(link string) error {
			u, err := url.Parse(link)
			if err != nil {
				return err
			}
			// Links may be relative
			abs := misc.JoinURL(baseURL, u).String()
			content.links.Add(abs)
			return nil
		})
	}(); err != nil {
		return false, errContinue
	}

	return content.links.Contains(path), nil
}

func linksOnPage(r io.Reader, visit func(string) error) error {

	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return err
	}

	doc.Find("a").Each(func(_ int, s *goquery.Selection) {
		if err != nil {
			return
		}
		if link, ok := s.Attr("href"); ok {
			err = visit(link)
		}
	})

	return err
}
