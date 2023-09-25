// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package misc

import (
	"bytes"
	"mime/multipart"
	"testing"
)

// TestCreateFormFile tests if CreateFormFile throws an error when creating
// a FormFile
func TestCreateFormFile(t *testing.T) {
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	_, err := CreateFormFile(writer, "csaf", "data", "application/json")
	if err != nil {
		t.Errorf("failed to create an io.Writer via CreateFormFile")
	}
}
