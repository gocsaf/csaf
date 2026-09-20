// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package mandatorytests

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
)

var test24SetFields = [...]string{
	"acting_entity_refs",
	"dl_vuln_ids",
	"group_ids",
	"product_ids",
	"receiving_entity_refs",
	"referenced_action_ids",
}

// validateTest24 implements section 6.1.24, "Multiple Definition in Actions".
func validateTest24(document any) []string {
	actions := involvementActions(document)
	seen := map[string]string{}
	var issues []string
	for _, value := range actions {
		action, ok := value.(map[string]any)
		if !ok {
			continue
		}
		id, _ := action["action_id"].(string)
		key, err := test24ActionKey(action)
		if err != nil {
			issues = append(issues, fmt.Sprintf("6.1.24: action %q cannot be compared: %v", id, err))
			continue
		}
		if previous, exists := seen[key]; exists {
			issues = append(issues, fmt.Sprintf("6.1.24: actions %q and %q differ only in action_id", previous, id))
		} else {
			seen[key] = id
		}
	}
	return issues
}

func test24ActionKey(action map[string]any) (string, error) {
	canonical := make(map[string]any, len(action))
	for field, value := range action {
		if field != "action_id" {
			canonical[field] = value
		}
	}
	for _, field := range test24SetFields {
		values, exists := canonical[field].([]any)
		if !exists {
			continue
		}
		values = slices.Clone(values)
		slices.SortFunc(values, func(left, right any) int {
			leftString, _ := left.(string)
			rightString, _ := right.(string)
			return cmp.Compare(leftString, rightString)
		})
		canonical[field] = values
	}
	data, err := json.Marshal(canonical)
	return string(data), err
}

func involvementActions(document any) []any {
	root, ok := document.(map[string]any)
	if !ok {
		return nil
	}
	documentObject, ok := root["document"].(map[string]any)
	if !ok {
		return nil
	}
	involvement, ok := documentObject["involvement"].(map[string]any)
	if !ok {
		return nil
	}
	actions, _ := involvement["actions"].([]any)
	return actions
}
