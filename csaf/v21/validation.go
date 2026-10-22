// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package v21

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// These URIs identify the CSAF 2.1 root schemas in the embedded schema files.
const (
	SchemaURI                    = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json"
	ProviderSchemaURI            = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/provider.json"
	AggregatorSchemaURI          = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/aggregator.json"
	ExtensionContentSchemaURI    = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/extension-content.json"
	ExtensionMetadataSchemaURI   = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/extension-metadata.json"
	ExtensionMetaschemaSchemaURI = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/extension-metaschema.json"
	MetaSchemaURI                = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/meta.json"
	ROLIESchemaURI               = "urn:gocsaf:schema:csaf:2.1:rolie-feed"
)

type schemaKind uint8

const (
	csafSchemaKind schemaKind = iota
	providerSchemaKind
	aggregatorSchemaKind
	rolieSchemaKind
)

var schemaRegistry = map[schemaKind]*compiledSchema{
	csafSchemaKind:       {url: SchemaURI},
	providerSchemaKind:   {url: ProviderSchemaURI},
	aggregatorSchemaKind: {url: AggregatorSchemaURI},
	rolieSchemaKind:      {url: ROLIESchemaURI},
}

type compiledSchema struct {
	url              string
	once             sync.Once
	err              error
	compiled         *jsonschema.Schema
	compilationCount atomic.Uint32
}

type embeddedSchemaLoader struct{}

func (embeddedSchemaLoader) Load(url string) (any, error) {
	path, ok := schemaPaths[url]
	if !ok {
		return nil, fmt.Errorf("schema resource %q is not embedded", url)
	}
	data, err := schemaFiles.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jsonschema.UnmarshalJSON(bytes.NewReader(data))
}

type ecmaRegexp regexp2.Regexp

func (re *ecmaRegexp) MatchString(value string) bool {
	matched, err := (*regexp2.Regexp)(re).MatchString(value)
	return err == nil && matched
}

func (re *ecmaRegexp) String() string {
	return (*regexp2.Regexp)(re).String()
}

func compileECMARegexp(expression string) (jsonschema.Regexp, error) {
	re, err := regexp2.Compile(expression, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	return (*ecmaRegexp)(re), nil
}

func (schema *compiledSchema) compile() {
	schema.compilationCount.Add(1)
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	compiler.UseLoader(embeddedSchemaLoader{})
	compiler.UseRegexpEngine(compileECMARegexp)
	schema.compiled, schema.err = compiler.Compile(schema.url)
}

func (schema *compiledSchema) validate(document any) ([]string, error) {
	schema.once.Do(schema.compile)
	if schema.err != nil {
		return nil, schema.err
	}

	err := schema.compiled.Validate(document)
	if err == nil {
		return nil, nil
	}

	var validationError *jsonschema.ValidationError
	if !errors.As(err, &validationError) {
		return nil, err
	}

	basic := validationError.BasicOutput()
	if basic.Valid {
		return nil, nil
	}

	errors := basic.Errors
	slices.SortFunc(errors, func(a, b jsonschema.OutputUnit) int {
		left := a.InstanceLocation
		right := b.InstanceLocation
		if strings.HasPrefix(right, left) {
			return -1
		}
		if strings.HasPrefix(left, right) {
			return +1
		}
		if difference := cmp.Compare(left, right); difference != 0 {
			return difference
		}
		return cmp.Compare(a.Error.String(), b.Error.String())
	})

	result := make([]string, 0, len(errors))
	for i := range errors {
		validationError := &errors[i]
		if validationError.Error == nil {
			continue
		}
		location := validationError.InstanceLocation
		if location == "" {
			location = validationError.AbsoluteKeywordLocation
		}
		result = append(result, location+": "+validationError.Error.String())
	}
	return result, nil
}

func (schema *compiledSchema) compilationCountValue() uint32 {
	return schema.compilationCount.Load()
}

// ValidateCSAF validates a JSON-compatible value against the CSAF 2.1 schema.
func ValidateCSAF(document any) ([]string, error) {
	return schemaRegistry[csafSchemaKind].validate(document)
}

// ValidateProviderMetadata validates a value against the provider metadata 2.1 schema.
func ValidateProviderMetadata(document any) ([]string, error) {
	return schemaRegistry[providerSchemaKind].validate(document)
}

// ValidateAggregator validates a value against the aggregator metadata 2.1 schema.
func ValidateAggregator(document any) ([]string, error) {
	return schemaRegistry[aggregatorSchemaKind].validate(document)
}

// ValidateROLIE validates a value against the CSAF 2.1 ROLIE feed schema.
func ValidateROLIE(document any) ([]string, error) {
	return schemaRegistry[rolieSchemaKind].validate(document)
}
