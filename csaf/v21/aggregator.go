// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package v21

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/gocsaf/csaf/v3/util"
)

// Validate checks the required aggregator identity fields.
func (aggregator *AggregatorAggregator) Validate() error {
	if aggregator.Category == "" {
		return errors.New("aggregator.aggregator.category is mandatory")
	}
	if aggregator.Name == "" {
		return errors.New("aggregator.aggregator.name is mandatory")
	}
	if aggregator.Namespace == "" {
		return errors.New("aggregator.aggregator.namespace is mandatory")
	}
	return nil
}

// WriteTo writes indented aggregator metadata JSON.
func (aggregator *Aggregator) WriteTo(writer io.Writer) (int64, error) {
	countingWriter := util.NWriter{Writer: writer}
	encoder := json.NewEncoder(&countingWriter)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(aggregator)
	return countingWriter.N, err
}
