// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Juan Manuel Méndez Rey <juan.mendezr@proton.me>

package options

import (
	"os"

	"github.com/jessevdk/go-flags"
)

// ManFlag carries the --man option that asks a command for its manual page.
// Parser adds it by itself. Commands that build their own flags.Parser add it
// with AddTo before parsing and call WriteIfAsked after.
type ManFlag struct {
	Man bool `long:"man" description:"Write the manual page in groff format to stdout and exit"`
}

// AddTo adds the --man option to the given parser.
func (f *ManFlag) AddTo(parser *flags.Parser) error {
	_, err := parser.AddGroup("Manual page", "", f)
	return err
}

// WriteIfAsked writes the manual page of the parser to stdout if --man was
// given, and reports whether it did. The date in the page comes from
// SOURCE_DATE_EPOCH when that is set, so the output is reproducible.
func (f *ManFlag) WriteIfAsked(parser *flags.Parser) bool {
	if !f.Man {
		return false
	}
	parser.WriteManPage(os.Stdout)
	return true
}
