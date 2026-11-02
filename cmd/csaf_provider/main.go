// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

// Package main implements the csaf_provider.
package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/cgi"
	"os"

	"github.com/jessevdk/go-flags"

	"github.com/gocsaf/csaf/v3/internal/manpage"
	"github.com/gocsaf/csaf/v3/util"
)

type options struct {
	Version bool `long:"version" description:"Display version of the binary"`
}

const cgiRequired = "The csaf_provider is a cgi binary and is designed to be served via a web server."

func ensureCGI() {
	if _, ok := os.LookupEnv("REQUEST_METHOD"); !ok {
		fmt.Println(cgiRequired)
		fmt.Println("Version: " + util.SemVersion)
		os.Exit(1)
	}
}

func main() {
	var opts options
	parser := flags.NewParser(&opts, flags.Default)
	parser.ShortDescription = "CGI program that serves and receives CSAF advisories"
	parser.LongDescription = "Implements the upload and management interface " +
		"of a CSAF trusted provider as a CGI program. A web server runs it per " +
		"request, and csaf_uploader is the client that talks to it. It keeps " +
		"the provider metadata, the ROLIE feeds and the index files in step as " +
		"advisories arrive, and signs them with the configured OpenPGP key."
	var man manpage.Flag
	if err := man.AddTo(parser); err != nil {
		log.Fatalf("error: %v\n", err)
	}
	parser.Parse()
	if man.WriteIfAsked(parser) {
		return
	}
	if opts.Version {
		fmt.Println(util.SemVersion)
		return
	}

	ensureCGI()

	cfg, err := loadConfig()
	if err != nil {
		cgi.Serve(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			http.Error(rw, "Something went wrong. Check server logs for more details",
				http.StatusInternalServerError)
		}))
		log.Fatalf("error: %v\n", err)
	}

	c, err := newController(cfg)
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
	pim := newPathInfoMux()
	c.bind(pim)

	if err := cgi.Serve(pim); err != nil {
		log.Fatalf("error: %v\n", err)
	}
}
