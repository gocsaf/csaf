// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package csaf

const (
	// TLPLabelClear is the 'CLEAR' policy (CSAF v2.1 & TLP v2 only).
	TLPLabelClear = "CLEAR"
	// TLPLabelAmberStrict is the 'AMBER+STRICT' policy (CSAF v2.1 & TLP v2 only).
	TLPLabelAmberStrict = "AMBER+STRICT"
)

// TLPLabelDefault returns the label of distributions based on CSAF version.
func TLPLabelDefault(version SpecVersion) TLPLabel {
	if version == Version21 {
		return TLPLabelClear
	}
	return TLPLabelWhite
}
