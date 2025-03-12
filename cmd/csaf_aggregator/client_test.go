// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gocsaf/csaf/v3/util"
)

func Test_downloadJSON(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		wantErr     error
	}{
		{
			name:        "status ok, application/json",
			statusCode:  http.StatusOK,
			contentType: "application/json",
			wantErr:     nil,
		},
		{
			name:        "status found, application/json",
			statusCode:  http.StatusFound,
			contentType: "application/json",
			wantErr:     errNotFound,
		},
		{
			name:        "status ok, application/xml",
			statusCode:  http.StatusOK,
			contentType: "application/xml",
			wantErr:     errNotFound,
		},
	}

	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			found := func(r io.Reader) error {
				return nil
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Content-Type", test.contentType)
				w.WriteHeader(test.statusCode)
			}))
			defer server.Close()
			hClient := http.Client{}
			client := util.Client(&hClient)
			if gotErr := downloadJSON(client, server.URL, found); gotErr != test.wantErr {
				t.Errorf("downloadJSON: Expected %q but got %q.", test.wantErr, gotErr)
			}
		})
	}
}
