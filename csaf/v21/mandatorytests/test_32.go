// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package mandatorytests

import "fmt"

// validateTest32 implements section 6.1.32, "Flag without Product Reference".
func validateTest32(document any) []string {
	root, ok := document.(map[string]any)
	if !ok {
		return nil
	}

	var issues []string
	forEachObject(root, "vulnerabilities", "$", func(vulnerability map[string]any, path string) {
		forEachObject(vulnerability, "flags", path, func(flag map[string]any, path string) {
			if !hasProductReference(flag) {
				issues = append(issues, fmt.Sprintf(
					"6.1.32: flag at %s has neither group_ids nor product_ids",
					path,
				))
			}
		})
	})
	return issues
}
