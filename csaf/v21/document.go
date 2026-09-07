// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package v21

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// plainCSAF has the fields of CSAF without its JSON methods.
type plainCSAF CSAF

// Parse validates a CSAF 2.1 JSON document and returns its typed representation.
func Parse(data []byte) (*CSAF, error) {
	var document CSAF
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	return &document, nil
}

// Validate checks the typed document against the bundled CSAF 2.1 schema.
func (document *CSAF) Validate() error {
	if document == nil {
		return errors.New("CSAF document is nil")
	}
	data, err := json.Marshal((*plainCSAF)(document))
	if err != nil {
		return fmt.Errorf("encode CSAF document: %w", err)
	}
	return validateJSON(data)
}

// UnmarshalJSON validates JSON before decoding it into the generated model.
func (document *CSAF) UnmarshalJSON(data []byte) error {
	if err := validateJSON(data); err != nil {
		return err
	}

	var decoded plainCSAF
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("decode typed CSAF document: %w", err)
	}
	*document = CSAF(decoded)
	return nil
}

func validateJSON(data []byte) error {
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	errors, err := ValidateCSAF(value)
	if err != nil {
		return err
	}
	if len(errors) != 0 {
		return fmt.Errorf("validate CSAF document: %s", strings.Join(errors, "; "))
	}
	return nil
}
