// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package v21

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

type DateTime string

var dateTimePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$`)

func NewDateTime(value time.Time) DateTime {
	return DateTime(value.Format(time.RFC3339Nano))
}

func (value DateTime) Time() (time.Time, error) {
	if !dateTimePattern.MatchString(string(value)) {
		return time.Time{}, fmt.Errorf("invalid CSAF date-time %q", value)
	}
	return time.Parse(time.RFC3339Nano, string(value))
}

func (value DateTime) String() string {
	return string(value)
}

func (value *DateTime) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	parsed := DateTime(text)
	if _, err := parsed.Time(); err != nil {
		return err
	}
	*value = parsed
	return nil
}
