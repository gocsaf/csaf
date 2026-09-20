// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package mandatorytests

import "fmt"

// validateTest29 implements section 6.1.29, "Remediation without Product Reference".
func validateTest29(document any) []string {
	root, ok := document.(map[string]any)
	if !ok {
		return nil
	}

	var issues []string
	forEachObject(root, "vulnerabilities", "$", func(vulnerability map[string]any, path string) {
		forEachObject(vulnerability, "remediations", path, func(remediation map[string]any, path string) {
			if !hasProductReference(remediation) {
				issues = append(issues, fmt.Sprintf(
					"6.1.29: remediation at %s has neither group_ids nor product_ids",
					path,
				))
			}
		})
	})
	return issues
}

func hasProductReference(object map[string]any) bool {
	return len(arrayAt(object, "group_ids")) != 0 || len(arrayAt(object, "product_ids")) != 0
}
