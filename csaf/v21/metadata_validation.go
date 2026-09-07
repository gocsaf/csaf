// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package v21

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"strings"
)

// Validate checks the current provider metadata against the bundled CSAF 2.1 schema.
func (provider *Provider) Validate() error {
	if provider == nil {
		return errors.New("provider metadata is nil")
	}
	return validateMetadata(provider, ValidateProviderMetadata)
}

// Validate checks the current aggregator metadata against the bundled CSAF 2.1 schema.
func (aggregator *Aggregator) Validate() error {
	if aggregator == nil {
		return errors.New("aggregator metadata is nil")
	}
	return validateMetadata(aggregator, ValidateAggregator)
}

func validateMetadata(document any, validate func(any) ([]string, error)) error {
	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("decode metadata: %w", err)
	}
	issues, err := validate(value)
	if err != nil {
		return err
	}
	if len(issues) != 0 {
		return fmt.Errorf("validate metadata: %s", strings.Join(issues, "; "))
	}
	return nil
}
