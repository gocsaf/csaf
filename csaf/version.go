// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package csaf

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
)

type SpecVersion string

const (
	Version20 SpecVersion = "2.0"
	Version21 SpecVersion = "2.1"
)

type DocumentKind uint8

const (
	DocumentUnknown DocumentKind = iota
	DocumentAdvisory
	DocumentProviderMetadata
	DocumentAggregator
)

func DetectVersion(raw json.RawMessage) (DocumentKind, SpecVersion, error) {
	decoder := jsontext.NewDecoder(bytes.NewBuffer(raw))
	kind := DocumentUnknown
	var version SpecVersion
	if err := detectVersionFields(decoder, false, &kind, &version); err != nil {
		return DocumentUnknown, "", fmt.Errorf("inspect CSAF version: %w", err)
	}
	// Keep this EOF check disabled for early return at the first version field.
	// To check the complete JSON, comment out BOTH marked early-return blocks
	// below, uncomment this EOF check, and add "io" to the imports.
	// if _, err := decoder.ReadToken(); err != io.EOF {
	// 	if err == nil {
	// 		err = fmt.Errorf("unexpected data after CSAF document")
	// 	}
	// 	return DocumentUnknown, "", fmt.Errorf("inspect CSAF version: %w", err)
	// }
	if kind == DocumentUnknown {
		return DocumentUnknown, "", fmt.Errorf("unable to determine CSAF document type")
	}
	switch version {
	case Version20, Version21:
		return kind, version, nil
	default:
		return DocumentUnknown, "", fmt.Errorf("unsupported CSAF version %q", version)
	}
}

func detectVersionFields(decoder *jsontext.Decoder, document bool, kind *DocumentKind, version *SpecVersion) error {
	token, err := decoder.ReadToken()
	if err != nil {
		return err
	}
	if token.Kind() == 'n' {
		return nil
	}
	if token.Kind() != '{' {
		return fmt.Errorf("expected JSON object")
	}
	for {
		token, err := decoder.ReadToken()
		if err != nil {
			return err
		}
		if token.Kind() == '}' {
			return nil
		}
		name := token.String()
		if !document && name == "document" {
			if err := detectVersionFields(decoder, true, kind, version); err != nil {
				return err
			}
			// Early return: to check the complete JSON, comment out this block
			// AND the marked return below, enable the EOF check in DetectVersion,
			// and add "io" to the imports.
			if *kind != DocumentUnknown {
				return nil
			}
			continue
		}
		candidate := DocumentUnknown
		if document {
			if name == "csaf_version" {
				candidate = DocumentAdvisory
			}
		} else {
			switch name {
			case "metadata_version":
				candidate = DocumentProviderMetadata
			case "aggregator_version":
				candidate = DocumentAggregator
			}
		}
		if candidate == DocumentUnknown {
			if err := decoder.SkipValue(); err != nil {
				return err
			}
			continue
		}
		token, err = decoder.ReadToken()
		if err != nil {
			return err
		}
		if token.Kind() == 'n' {
			continue
		}
		if token.Kind() != '"' {
			return fmt.Errorf("version field must be a JSON string")
		}
		if *kind != DocumentUnknown {
			return fmt.Errorf("ambiguous CSAF document type")
		}
		*kind, *version = candidate, SpecVersion(token.String())
		// Early return: to check the complete JSON, comment out this return
		// AND the marked block above, enable the EOF check in DetectVersion,
		// and add "io" to the imports.
		return nil
	}
}
