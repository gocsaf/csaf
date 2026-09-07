// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package v21

import (
	"strings"
	"time"
)

type DateTime string

func NewDateTime(value time.Time) DateTime {
	return DateTime(value.Format(time.RFC3339Nano))
}

func (value DateTime) Time() (time.Time, error) {
	normalized := strings.NewReplacer("t", "T", "z", "Z").Replace(string(value))
	return time.Parse(time.RFC3339Nano, normalized)
}

func (value DateTime) String() string {
	return string(value)
}
