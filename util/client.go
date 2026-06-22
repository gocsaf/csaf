// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package util //revive:disable-line:var-naming

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/time/rate"
)

// Client is an interface to abstract http.Client.
type Client interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (*http.Response, error)
	Head(url string) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)
	PostForm(url string, data url.Values) (*http.Response, error)
}

// ClientWithContext extents the Client interface to ease using it context aware.
// Also for the sake of backwards compatibility.
type ClientWithContext interface {
	Client
	GetWithContext(ctx context.Context, url string) (*http.Response, error)
	HeadWithContext(ctx context.Context, url string) (*http.Response, error)
	PostWithContext(ctx context.Context, url, contentType string, body io.Reader) (*http.Response, error)
	PostFormWithContext(ctx context.Context, url string, data url.Values) (*http.Response, error)
}

// BasicClient is a client implementing the default [Client] and [ClientWithContext] interface methods
type BasicClient struct {
	Client
}

// LoggingClient is a client that logs called URLs.
type LoggingClient struct {
	Client
	Log func(method, url string)
}

// LimitingClient is a Client implementing rate throttling.
type LimitingClient struct {
	Client
	Limiter *rate.Limiter
}

// HeaderClient adds extra HTTP header fields to requests.
type HeaderClient struct {
	Client
	Header http.Header
}

// Do implements the respective method of the [Client] interface.
func (hc *HeaderClient) Do(req *http.Request) (*http.Response, error) {
	// Maybe this overly careful but this minimizes
	// potential side effects in the caller.
	orig := req.Header
	defer func() { req.Header = orig }()

	// Work on a copy.
	req.Header = req.Header.Clone()

	for key, values := range hc.Header {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	// Use default user agent if none is set
	if userAgent := hc.Header.Get("User-Agent"); userAgent == "" {
		req.Header.Add("User-Agent", "csaf_distribution/"+SemVersion)
	}
	return hc.Client.Do(req)
}

// GetWithContext is the respective method of the [ClientWithContext] interface.
func (hc *HeaderClient) GetWithContext(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return hc.Do(req)
}

// Get implements the respective method of the [Client] interface.
func (hc *HeaderClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return hc.Do(req)
}

// HeadWithContext implements the respective method of the [ClientWithContext] interface.
func (hc *HeaderClient) HeadWithContext(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	return hc.Do(req)
}

// Head implements the respective method of the [Client] interface.
func (hc *HeaderClient) Head(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	return hc.Do(req)
}

// PostWithContext implements the respective method of the [ClientWithContext] interface.
func (hc *HeaderClient) PostWithContext(ctx context.Context, url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return hc.Do(req)
}

// Post implements the respective method of the [Client] interface.
func (hc *HeaderClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return hc.Do(req)
}

// PostFormWithContext implements the respective method of the [ClientWithContext] interface.
func (hc *HeaderClient) PostFormWithContext(ctx context.Context, url string, data url.Values) (*http.Response, error) {
	return hc.PostWithContext(
		ctx, url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

// PostForm implements the respective method of the [Client] interface.
func (hc *HeaderClient) PostForm(url string, data url.Values) (*http.Response, error) {
	return hc.Post(
		url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

// log logs to a callback if given.
func (lc *LoggingClient) log(method, url string) {
	if lc.Log != nil {
		lc.Log(method, url)
	} else {
		log.Printf("[%s]: %s\n", method, url)
	}
}

// Do implements the respective method of the [Client] interface.
func (lc *LoggingClient) Do(req *http.Request) (*http.Response, error) {
	lc.log("DO", req.URL.String())
	return lc.Client.Do(req)
}

// GetWithContext implements the respective method of the [ClientWithContext] interface.
func (lc *LoggingClient) GetWithContext(ctx context.Context, url string) (*http.Response, error) {
	lc.log("GET", url)
	if cc, ok := lc.Client.(ClientWithContext); ok {
		return cc.GetWithContext(ctx, url)
	}
	return lc.Client.Get(url)
}

// Get implements the respective method of the [Client] interface.
func (lc *LoggingClient) Get(url string) (*http.Response, error) {
	lc.log("GET", url)
	return lc.Client.Get(url)
}

// HeadWithContext implements the respective method of the [ClientWithContext] interface.
func (lc *LoggingClient) HeadWithContext(ctx context.Context, url string) (*http.Response, error) {
	lc.log("HEAD", url)
	if cc, ok := lc.Client.(ClientWithContext); ok {
		return cc.HeadWithContext(ctx, url)
	}
	return lc.Client.Head(url)
}

// Head implements the respective method of the [Client] interface.
func (lc *LoggingClient) Head(url string) (*http.Response, error) {
	lc.log("HEAD", url)
	return lc.Client.Head(url)
}

// PostWithContext implements the respective method of the [ClientWithContext] interface.
func (lc *LoggingClient) PostWithContext(ctx context.Context, url, contentType string, body io.Reader) (*http.Response, error) {
	lc.log("POST", url)
	if cc, ok := lc.Client.(ClientWithContext); ok {
		return cc.PostWithContext(ctx, url, contentType, body)
	}
	return lc.Client.Post(url, contentType, body)
}

// Post implements the respective method of the [Client] interface.
func (lc *LoggingClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	lc.log("POST", url)
	return lc.Client.Post(url, contentType, body)
}

// PostFormWithContext implements the respective method of the [ClientWithContext] interface.
func (lc *LoggingClient) PostFormWithContext(ctx context.Context, url string, data url.Values) (*http.Response, error) {
	lc.log("POST FORM", url)
	if cc, ok := lc.Client.(ClientWithContext); ok {
		return cc.PostFormWithContext(ctx, url, data)
	}
	return lc.Client.PostForm(url, data)
}

// PostForm implements the respective method of the [Client] interface.
func (lc *LoggingClient) PostForm(url string, data url.Values) (*http.Response, error) {
	lc.log("POST FORM", url)
	return lc.Client.PostForm(url, data)
}

// Do implements the respective method of the [Client] interface.
func (lc *LimitingClient) Do(req *http.Request) (*http.Response, error) {
	if err := lc.Limiter.Wait(context.Background()); err != nil {
		return nil, err
	}
	return lc.Client.Do(req)
}

// GetWithContext implements the respective method of the [ClientWithContext] interface.
func (lc *LimitingClient) GetWithContext(ctx context.Context, url string) (*http.Response, error) {
	if err := lc.Limiter.Wait(ctx); err != nil {
		return nil, err
	}
	if cc, ok := lc.Client.(ClientWithContext); ok {
		return cc.GetWithContext(ctx, url)
	}
	return lc.Client.Get(url)
}

// Get implements the respective method of the [Client] interface.
func (lc *LimitingClient) Get(url string) (*http.Response, error) {
	if err := lc.Limiter.Wait(context.Background()); err != nil {
		return nil, err
	}
	return lc.Client.Get(url)
}

// HeadWithContext implements the respective method of the [ClientWithContext] interface.
func (lc *LimitingClient) HeadWithContext(ctx context.Context, url string) (*http.Response, error) {
	if err := lc.Limiter.Wait(ctx); err != nil {
		return nil, err
	}
	if cc, ok := lc.Client.(ClientWithContext); ok {
		return cc.HeadWithContext(ctx, url)
	}
	return lc.Client.Head(url)
}

// Head implements the respective method of the [Client] interface.
func (lc *LimitingClient) Head(url string) (*http.Response, error) {
	if err := lc.Limiter.Wait(context.Background()); err != nil {
		return nil, err
	}
	return lc.Client.Head(url)
}

// PostWithContext implements the respective method of the [ClientWithContext] interface.
func (lc *LimitingClient) PostWithContext(ctx context.Context, url, contentType string, body io.Reader) (*http.Response, error) {
	if err := lc.Limiter.Wait(ctx); err != nil {
		return nil, err
	}
	if cc, ok := lc.Client.(ClientWithContext); ok {
		return cc.PostWithContext(ctx, url, contentType, body)
	}
	return lc.Client.Post(url, contentType, body)
}

// Post implements the respective method of the [Client] interface.
func (lc *LimitingClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	if err := lc.Limiter.Wait(context.Background()); err != nil {
		return nil, err
	}
	return lc.Client.Post(url, contentType, body)
}

// PostFormWithContext implements the respective method of the [ClientWithContext] interface.
func (lc *LimitingClient) PostFormWithContext(ctx context.Context, url string, data url.Values) (*http.Response, error) {
	if err := lc.Limiter.Wait(ctx); err != nil {
		return nil, err
	}
	if cc, ok := lc.Client.(ClientWithContext); ok {
		return cc.PostFormWithContext(ctx, url, data)
	}
	return lc.Client.PostForm(url, data)
}

// PostForm implements the respective method of the [Client] interface.
func (lc *LimitingClient) PostForm(url string, data url.Values) (*http.Response, error) {
	if err := lc.Limiter.Wait(context.Background()); err != nil {
		return nil, err
	}
	return lc.Client.PostForm(url, data)
}

// Do implements the respective method of the [Client] interface.
func (bc *BasicClient) Do(req *http.Request) (*http.Response, error) {
	return bc.Client.Do(req)
}

// GetWithContext implements the respective method of the [ClientWithContext] interface.
func (bc *BasicClient) GetWithContext(ctx context.Context, url string) (*http.Response, error) {
	if cc, ok := bc.Client.(ClientWithContext); ok {
		return cc.GetWithContext(ctx, url)
	}
	return bc.Client.Get(url)
}

// Get implements the respective method of the [Client] interface.
func (bc *BasicClient) Get(url string) (*http.Response, error) {
	return bc.Client.Get(url)
}

// HeadWithContext implements the respective method of the [ClientWithContext] interface.
func (bc *BasicClient) HeadWithContext(ctx context.Context, url string) (*http.Response, error) {
	if cc, ok := bc.Client.(ClientWithContext); ok {
		return cc.HeadWithContext(ctx, url)
	}
	return bc.Client.Head(url)
}

// Head implements the respective method of the [Client] interface.
func (bc *BasicClient) Head(url string) (*http.Response, error) {
	return bc.Client.Head(url)
}

// PostWithContext implements the respective method of the [ClientWithContext] interface.
func (bc *BasicClient) PostWithContext(ctx context.Context, url, contentType string, body io.Reader) (*http.Response, error) {
	if cc, ok := bc.Client.(ClientWithContext); ok {
		return cc.PostWithContext(ctx, url, contentType, body)
	}
	return bc.Client.Post(url, contentType, body)
}

// Post implements the respective method of the [Client] interface.
func (bc *BasicClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	return bc.Client.Post(url, contentType, body)
}

// PostFormWithContext implements the respective method of the [ClientWithContext] interface.
func (bc *BasicClient) PostFormWithContext(ctx context.Context, url string, data url.Values) (*http.Response, error) {
	if cc, ok := bc.Client.(ClientWithContext); ok {
		return cc.PostFormWithContext(ctx, url, data)
	}
	return bc.Client.PostForm(url, data)
}

// PostForm implements the respective method of the [Client] interface.
func (bc *BasicClient) PostForm(url string, data url.Values) (*http.Response, error) {
	return bc.Client.PostForm(url, data)
}
