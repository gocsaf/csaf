// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

// When true, fields with different omitempty settings or outer pointer/value
// shapes remain raw in bare and in version details in the shared model.
// When false, compatible fields are merged, using pointers to preserve absence.
const separateOptionalityDifferences = false
