// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package misc

import (
	"encoding/json"
	"fmt"
	"io"
)

// StrictJSONParse provides JSON parsing with stronger validations
func StrictJSONParse(jsonData io.Reader, target interface{}) error {
	decoder := json.NewDecoder(jsonData)

	// 1. Disallow unknown fields
	decoder.DisallowUnknownFields()

	// Decode the JSON into the provided struct
	err := decoder.Decode(target)
	if err != nil {
		return fmt.Errorf("strictJSONParse: %w", err)
	}

	// 3. Ensure there's no trailing data after the JSON object
	token, err := decoder.Token()
	if err != io.EOF {
		return fmt.Errorf("strictJSONParse: unexpected trailing data after JSON: token: %v, err: %v", token, err)
	}

	return nil
}
