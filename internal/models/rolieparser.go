// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
)

// StreamingROLIEParser is a specialized ROLIE parser
// to only extracr relevant fields in a streaming manner.
type StreamingROLIEParser struct {
	currentLink csaf.Link
	Updated     time.Time
	Links       []csaf.Link
	// HandleEntry is called if an entry if completed.
	HandleEntry func(*StreamingROLIEParser)
}

type tokenFn func(json.Token) (tokenFn, error)

func closing(d json.Delim) json.Delim {
	if d == '{' {
		return '}'
	}
	return ']'
}

func (srp *StreamingROLIEParser) linkContent(t json.Token) (tokenFn, error) {
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '}':
			srp.Links = append(srp.Links, srp.currentLink)
			return srp.linkList, nil
		default:
			return ignore(closing(v), srp.linkContent), nil
		}
	case string:
		switch v {
		case "rel":
			return stringStore(&srp.currentLink.Rel, srp.linkContent), nil
		case "href":
			return stringStore(&srp.currentLink.HRef, srp.linkContent), nil
		}
	}
	return srp.linkContent, nil
}

func (srp *StreamingROLIEParser) resetLinkContent() {
	srp.currentLink.HRef = ""
	srp.currentLink.Rel = ""
}

func (srp *StreamingROLIEParser) linkList(t json.Token) (tokenFn, error) {
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case ']':
			return srp.entryItem, nil
		case '{':
			srp.resetLinkContent()
			return srp.linkContent, nil
		default:
			return ignore(closing(v), srp.linkList), nil
		}
	}
	return srp.linkList, nil
}

func stringStore(s *string, returnState tokenFn) tokenFn {
	return func(t json.Token) (tokenFn, error) {
		v, ok := t.(string)
		if !ok {
			return nil, fmt.Errorf("expected string. found %T", t)
		}
		*s = v
		return returnState, nil
	}
}

func timeStore(target *time.Time, returnState tokenFn) tokenFn {
	return func(t json.Token) (tokenFn, error) {
		v, ok := t.(string)
		if !ok {
			return nil, fmt.Errorf("expected time string. found %T", t)
		}
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, fmt.Errorf("parsing time failed: %w", err)
		}
		*target = parsed
		return returnState, nil
	}
}

func (srp *StreamingROLIEParser) link(t json.Token) (tokenFn, error) {
	delim, ok := t.(json.Delim)
	if !ok || delim != '[' {
		return nil, errors.New("link: expected [")
	}
	return srp.linkList, nil
}

func (srp *StreamingROLIEParser) entryItem(t json.Token) (tokenFn, error) {
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '}':
			if srp.HandleEntry != nil {
				srp.HandleEntry(srp)
			}
			return srp.entryContent, nil
		default:
			return ignore(closing(v), srp.entryItem), nil
		}
	case string:
		switch v {
		case "link":
			return srp.link, nil
		case "updated":
			return timeStore(&srp.Updated, srp.entryItem), nil
		}
	}
	return srp.entryItem, nil
}

func (srp *StreamingROLIEParser) resetEntryItem() {
	srp.Updated = time.Time{}
	srp.Links = nil
}

func (srp *StreamingROLIEParser) entryContent(t json.Token) (tokenFn, error) {
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			srp.resetEntryItem()
			return srp.entryItem, nil
		case '}':
			fmt.Println(srp.Links)
			return srp.entry, nil
		default:
			return ignore(closing(v), srp.entryContent), nil
		}
	}
	return srp.entryContent, nil
}

func (srp *StreamingROLIEParser) entry(t json.Token) (tokenFn, error) {
	delim, ok := t.(json.Delim)
	if !ok || delim != '[' {
		return nil, errors.New("entry: expected [")
	}
	return srp.entryContent, nil
}

func (srp *StreamingROLIEParser) feedContent(t json.Token) (tokenFn, error) {
	switch v := t.(type) {
	case json.Delim:
		if v == '}' {
			// return rp.top, nil
			// We are done.
			return nil, nil
		}
		return ignore(closing(v), srp.feedContent), nil
	case string:
		switch v {
		case "entry":
			return srp.entry, nil
		}
	}
	return srp.feedContent, nil
}

func (srp *StreamingROLIEParser) feed(t json.Token) (tokenFn, error) {
	delim, ok := t.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("feed: expected {")
	}
	return srp.feedContent, nil
}

func (srp *StreamingROLIEParser) top(t json.Token) (tokenFn, error) {
	switch v := t.(type) {
	case json.Delim:
		return ignore(closing(v), srp.top), nil
	case string:
		if v == "feed" {
			return srp.feed, nil
		}
	}
	return srp.top, nil
}

func ignore(end json.Delim, returnState tokenFn) tokenFn {
	var me tokenFn
	me = func(t json.Token) (tokenFn, error) {
		switch v := t.(type) {
		case json.Delim:
			switch v {
			case end:
				return returnState, nil
			case '{':
				return ignore('}', me), nil
			case '[':
				return ignore(']', me), nil
			}
		}
		return me, nil
	}
	return me
}

func (srp *StreamingROLIEParser) initial(t json.Token) (tokenFn, error) {
	delim, ok := t.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("expected {")
	}
	return srp.top, nil
}

// Parse parses a ROLIE feed from a [io.Reader].
// Found entries are Reported to the given handler.
func (srp *StreamingROLIEParser) Parse(r io.Reader) error {
	dec := json.NewDecoder(r)
	for state := srp.initial; state != nil; {
		t, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("decoding JSON failed: %w", err)
		}
		if state, err = state(t); err != nil {
			return err
		}
	}
	return nil
}

/*
func main() {
	handler := func(rp *StreamingROLIEParser) {
		fmt.Printf("entry:\n\tupdated: %s\n", rp.Updated)
		fmt.Printf("\tlinks:\n")
		for _, l := range rp.Links {
			fmt.Printf("\t\trel: %q href: %q\n", l.Rel, l.HRef)
		}
	}
	srp := StreamingROLIEParser{
		EntryHandler: handler,
	}
	if err := srp.Parse(os.Stdin); err != nil {
		log.Fatalf("error: %v\n", err)
	}
}
*/
