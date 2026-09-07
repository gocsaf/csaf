// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package csaf

import v21 "github.com/gocsaf/csaf/v3/csaf/v21"

// TLPLabel identifies a Traffic Light Protocol sharing level.
type TLPLabel = v21.TLPLabelT

const (
	TLPLabelClear       = v21.TLPLabelTCLEAR
	TLPLabelGreen       = v21.TLPLabelTGREEN
	TLPLabelAmber       = v21.TLPLabelTAMBER
	TLPLabelAmberStrict = v21.TLPLabelTAMBERSTRICT
	TLPLabelRed         = v21.TLPLabelTRED
)
