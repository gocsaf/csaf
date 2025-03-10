// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package csaf

import (
	"bytes"
	_ "embed" // Used for embedding.
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schema/csaf_json_schema.json
var csafSchema []byte

//go:embed schema/cvss-v2.0.json
var cvss20 []byte

//go:embed schema/cvss-v3.0.json
var cvss30 []byte

//go:embed schema/cvss-v3.1.json
var cvss31 []byte

//go:embed schema/provider_json_schema.json
var providerSchema []byte

//go:embed schema/aggregator_json_schema.json
var aggregatorSchema []byte

//go:embed schema/ROLIE_feed_json_schema.json
var rolieSchema []byte

type compiledSchema struct {
	url      string
	once     sync.Once
	err      error
	compiled *jsonschema.Schema
}

const (
	csafSchemaURL       = "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json"
	providerSchemaURL   = "https://docs.oasis-open.org/csaf/csaf/v2.0/provider_json_schema.json"
	aggregatorSchemaURL = "https://docs.oasis-open.org/csaf/csaf/v2.0/aggregator_json_schema.json"
	cvss20SchemaURL     = "https://www.first.org/cvss/cvss-v2.0.json"
	cvss30SchemaURL     = "https://www.first.org/cvss/cvss-v3.0.json"
	cvss31SchemaURL     = "https://www.first.org/cvss/cvss-v3.1.json"
	rolieSchemaURL      = "https://raw.githubusercontent.com/tschmidtb51/csaf/ROLIE-schema/csaf_2.0/json_schema/ROLIE_feed_json_schema.json"
)

var (
	compiledCSAFSchema       = compiledSchema{url: csafSchemaURL}
	compiledProviderSchema   = compiledSchema{url: providerSchemaURL}
	compiledAggregatorSchema = compiledSchema{url: aggregatorSchemaURL}
	compiledRolieSchema      = compiledSchema{url: rolieSchemaURL}
)

// loadURL loads the content of an URL from embedded data or
// falls back to the global loader function of the jsonschema package.
func loadURL(s string) (io.ReadCloser, error) {
	loader := func(data []byte) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	switch s {
	case csafSchemaURL:
		return loader(csafSchema)
	case cvss20SchemaURL:
		return loader(cvss20)
	case cvss30SchemaURL:
		return loader(cvss30)
	case cvss31SchemaURL:
		return loader(cvss31)
	case providerSchemaURL:
		return loader(providerSchema)
	case aggregatorSchemaURL:
		return loader(aggregatorSchema)
	case rolieSchemaURL:
		return loader(rolieSchema)
	default:
		return jsonschema.LoadURL(s)
	}
}

var (
	uriRegexp     *regexp.Regexp
	uriRegexpOnce sync.Once
)

func compileURIRegexp() {
	// Taken from
	//   https://github.com/ajv-validator/ajv-formats/blob/master/src/formats.ts#L116
	// which refers to
	//   https://github.com/mafintosh/is-my-json-valid/blob/master/formats.js
	uriRegexp = regexp.MustCompile(
		`^(?:[a-zA-Z][a-zA-Z0-9+\-.]*:)(?:\/?\/)?[^\s]*$`)
}

func isValidURI(v any) bool {
	uri, ok := v.(string)
	if !ok {
		return false
	}
	for _, r := range uri {
		if r > unicode.MaxASCII {
			return false
		}
	}
	uriRegexpOnce.Do(compileURIRegexp)
	return uriRegexp.MatchString(uri)
}

func (cs *compiledSchema) compile() {
	c := jsonschema.NewCompiler()
	c.AssertFormat = true
	c.LoadURL = loadURL
	// TODO: We should further investigate if this is really necessary.
	// This is mainly done to emulate the behaviour of the
	// validator service.
	c.Formats["uri"] = isValidURI
	cs.compiled, cs.err = c.Compile(cs.url)
}

func (cs *compiledSchema) validate(doc any) ([]string, error) {
	cs.once.Do(cs.compile)

	if cs.err != nil {
		return nil, cs.err
	}

	err := cs.compiled.Validate(doc)
	if err == nil {
		return nil, nil
	}

	valErr, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return nil, err
	}

	basic := valErr.BasicOutput()
	if basic.Valid {
		return nil, nil
	}

	errs := basic.Errors

	sort.Slice(errs, func(i, j int) bool {
		pi := errs[i].InstanceLocation
		pj := errs[j].InstanceLocation
		if strings.HasPrefix(pj, pi) {
			return true
		}
		if strings.HasPrefix(pi, pj) {
			return false
		}
		if pi != pj {
			return pi < pj
		}
		return errs[i].Error < errs[j].Error
	})

	res := make([]string, 0, len(errs))

	for i := range errs {
		e := &errs[i]
		if e.Error == "" {
			continue
		}
		loc := e.InstanceLocation
		if loc == "" {
			loc = e.AbsoluteKeywordLocation
		}
		res = append(res, loc+": "+e.Error)
	}

	return res, nil
}

// ValidateCSAF validates the document doc against the JSON schema
// of CSAF.
func ValidateCSAF(doc any) ([]string, error) {
	return compiledCSAFSchema.validate(doc)
}

// ValidateProviderMetadata validates the document doc against the JSON schema
// of provider metadata.
func ValidateProviderMetadata(doc any) ([]string, error) {
	return compiledProviderSchema.validate(doc)
}

// ValidateAggregator validates the document doc against the JSON schema
// of aggregator.
func ValidateAggregator(doc any) ([]string, error) {
	return compiledAggregatorSchema.validate(doc)
}

// ValidateROLIE validates the ROLIE feed against the JSON schema
// of ROLIE
func ValidateROLIE(doc any) ([]string, error) {
	return compiledRolieSchema.validate(doc)
}
