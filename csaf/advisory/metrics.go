// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package advisory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gocsaf/csaf/v5/csaf/types"
)

type Scores []Score

type Score struct {
	CVSSV2   *types.CVSSV20 `json:"cvss_v2,omitempty,omitzero"`
	CVSSV3   types.CVSSV3   `json:"cvss_v3,omitempty,omitzero"`
	Products ProductsT      `json:"products"`
}

type MetricContent struct {
	CVSSV2                    *types.CVSSV20             `json:"cvss_v2,omitempty,omitzero"`
	CVSSV3                    types.CVSSV3               `json:"cvss_v3,omitempty,omitzero"`
	CVSSV4                    *types.CVSSV40             `json:"cvss_v4,omitempty,omitzero"`
	EPSS                      *MetricContentEPSS         `json:"epss,omitempty,omitzero"`
	QualitativeSeverityRating *QualitativeSeverityRating `json:"qualitative_severity_rating,omitempty,omitzero"`
	SSVCV2                    *types.SSVCV2              `json:"ssvc_v2,omitempty,omitzero"`
	XExtensions               ExtensionsT                `json:"x_extensions,omitempty,omitzero"`
}

type MetricContentEPSS struct {
	Percentile  string         `json:"percentile"`
	Probability string         `json:"probability"`
	Timestamp   types.DateTime `json:"timestamp"`
}

type QualitativeSeverityRating string

const QualitativeSeverityRatingCritical QualitativeSeverityRating = "critical"
const QualitativeSeverityRatingHigh QualitativeSeverityRating = "high"
const QualitativeSeverityRatingLow QualitativeSeverityRating = "low"
const QualitativeSeverityRatingMedium QualitativeSeverityRating = "medium"
const QualitativeSeverityRatingNone QualitativeSeverityRating = "none"

func (value QualitativeSeverityRating) validIn(v version) bool {
	switch value {
	case QualitativeSeverityRatingCritical, QualitativeSeverityRatingHigh, QualitativeSeverityRatingLow, QualitativeSeverityRatingMedium, QualitativeSeverityRatingNone:
		return v == version21
	}
	return false
}

// ScoresFromBare decodes the raw scores of the bare model.
func ScoresFromBare(data json.RawMessage) (Scores, error) {
	var scores Scores
	err := json.Unmarshal(data, &scores)
	return scores, err
}

// MetricContentFromBare decodes the raw metric content of the bare model.
func MetricContentFromBare(data json.RawMessage) (MetricContent, error) {
	var content MetricContent
	err := json.Unmarshal(data, &content)
	return content, err
}

func (source *Scores) Check(v version) error {
	for i := range *source {
		if err := (*source)[i].Check(v); err != nil {
			return fmt.Errorf("[%d].%w", i, err)
		}
	}
	return nil
}

func (source *Score) Check(v version) error {
	if len(source.Products) == 0 {
		return errors.New("products: required value is missing or empty")
	}
	return nil
}

func (source *MetricContent) Check(v version) error {
	if source.EPSS != nil {
		if err := source.EPSS.Check(v); err != nil {
			return fmt.Errorf(".epss.%w", err)
		}
	}
	if source.QualitativeSeverityRating != nil {
		if *source.QualitativeSeverityRating != "" && !(*source.QualitativeSeverityRating).validIn(v) {
			return fmt.Errorf(".qualitative_severity_rating: invalid value %q", *source.QualitativeSeverityRating)
		}
	}
	for i := range source.XExtensions {
		if err := source.XExtensions[i].Check(v); err != nil {
			return fmt.Errorf(".x_extensions[%d].%w", i, err)
		}
	}
	return nil
}

func (source *MetricContentEPSS) Check(v version) error {
	if source.Percentile == "" {
		return errors.New("percentile: required value is missing or empty")
	}
	if source.Probability == "" {
		return errors.New("probability: required value is missing or empty")
	}
	if source.Timestamp == "" {
		return errors.New("timestamp: required value is missing or empty")
	}
	return nil
}

func (score *Score) UnmarshalJSON(data []byte) error {
	type plain Score
	var decoded plain
	cvss, err := decodeWithCVSSV3(data, &decoded)
	if err != nil {
		return err
	}
	*score = Score(decoded)
	score.CVSSV3 = cvss
	return nil
}

func (content *MetricContent) UnmarshalJSON(data []byte) error {
	type plain MetricContent
	var decoded plain
	cvss, err := decodeWithCVSSV3(data, &decoded)
	if err != nil {
		return err
	}
	*content = MetricContent(decoded)
	content.CVSSV3 = cvss
	return nil
}

// decodeWithCVSSV3 decodes data into target without the cvss_v3 field and
// returns cvss_v3 separately. encoding/json cannot choose the concrete type of
// the CVSSV3 interface, so the version field selects it.
func decodeWithCVSSV3(data []byte, target any) (types.CVSSV3, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	rawCVSS := fields["cvss_v3"]
	delete(fields, "cvss_v3")

	plainData, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(plainData, target); err != nil {
		return nil, err
	}

	if len(rawCVSS) == 0 || bytes.Equal(rawCVSS, []byte("null")) {
		return nil, nil
	}
	var discriminator struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(rawCVSS, &discriminator); err != nil {
		return nil, fmt.Errorf("decode CVSS v3 discriminator: %w", err)
	}
	var cvss types.CVSSV3
	switch discriminator.Version {
	case "3.0":
		cvss = new(types.CVSSV30)
	case "3.1":
		cvss = new(types.CVSSV31)
	default:
		return nil, fmt.Errorf("unsupported CVSS v3 version %q", discriminator.Version)
	}
	if err := json.Unmarshal(rawCVSS, cvss); err != nil {
		return nil, err
	}
	return cvss, nil
}
