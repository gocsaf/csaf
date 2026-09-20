// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package mandatorytests

import "fmt"

// forEachObject visits each object in the named array field and provides its
// indexed JSON path relative to parentPath.
func forEachObject(
	parent map[string]any,
	field string,
	parentPath string,
	visit func(map[string]any, string),
) {
	for i, value := range arrayAt(parent, field) {
		if object, ok := value.(map[string]any); ok {
			visit(object, fmt.Sprintf("%s.%s[%d]", parentPath, field, i))
		}
	}
}

func arrayAt(object map[string]any, field string) []any {
	values, _ := object[field].([]any)
	return values
}
