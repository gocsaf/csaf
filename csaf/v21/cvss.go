// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package v21

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type CVSSV3 interface {
	CVSSVersion() string
}

type CVSSV40Severity string

const (
	CVSSV40SeverityCritical CVSSV40Severity = "CRITICAL"
	CVSSV40SeverityHigh     CVSSV40Severity = "HIGH"
	CVSSV40SeverityLow      CVSSV40Severity = "LOW"
	CVSSV40SeverityMedium   CVSSV40Severity = "MEDIUM"
	CVSSV40SeverityNone     CVSSV40Severity = "NONE"
)

func (*CVSSV30) CVSSVersion() string { return "3.0" }

func (*CVSSV31) CVSSVersion() string { return "3.1" }

// UnmarshalJSON selects the concrete CVSSV3 branch using its version field.
// A custom decoder is necessary because encoding/json cannot choose a concrete
// implementation for an interface field.
//
//   - https://pkg.go.dev/encoding/json#Unmarshaler
//   - https://stackoverflow.com/questions/52433467/how-to-call-json-unmarshal-inside-unmarshaljson-without-causing-stack-overflow
//   - https://github.com/golang/go/discussions/63397
func (content *CSAFVulnerabilitiesElemMetricsElemContent) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}

	rawCVSS, hasCVSS := fields["cvss_v3"]
	delete(fields, "cvss_v3")

	plainData, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	type plain CSAFVulnerabilitiesElemMetricsElemContent
	var decoded plain
	if err := json.Unmarshal(plainData, &decoded); err != nil {
		return err
	}

	var cvss CVSSV3
	if hasCVSS && len(rawCVSS) > 0 && !bytes.Equal(rawCVSS, []byte("null")) {
		var discriminator struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(rawCVSS, &discriminator); err != nil {
			return fmt.Errorf("decode CVSS v3 discriminator: %w", err)
		}
		switch discriminator.Version {
		case "3.0":
			value := new(CVSSV30)
			if err := json.Unmarshal(rawCVSS, value); err != nil {
				return err
			}
			cvss = value
		case "3.1":
			value := new(CVSSV31)
			if err := json.Unmarshal(rawCVSS, value); err != nil {
				return err
			}
			cvss = value
		default:
			return fmt.Errorf("unsupported CVSS v3 version %q", discriminator.Version)
		}
	}

	*content = CSAFVulnerabilitiesElemMetricsElemContent(decoded)
	content.CVSSV3 = cvss
	return nil
}
