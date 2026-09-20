// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

// Package mandatorytests implements the mandatory tests from section 6.1 of
// CSAF 2.1 which are not enforced by JSON Schema validation.
package mandatorytests

// Validate runs the implemented mandatory tests against a schema-valid CSAF
// JSON value.
func Validate(document any) []string {
	var issues []string
	issues = append(issues, validateTest24(document)...)
	issues = append(issues, validateTest29(document)...)
	issues = append(issues, validateTest32(document)...)
	return issues
}
