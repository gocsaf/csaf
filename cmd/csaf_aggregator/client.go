// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gocsaf/csaf/v3/util"
)

var errNotFound = errors.New("not found")

func downloadJSON(c util.Client, url string, found func(io.Reader) error) error {
	res, err := c.Get(url)
	if err != nil {
		return fmt.Errorf("not found: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK ||
		res.Header.Get("Content-Type") != "application/json" {
		// ignore this as it is expected.
		return errNotFound
	}
	return found(res.Body)
}
