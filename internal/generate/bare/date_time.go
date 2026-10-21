// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"go/ast"
)

func compatibleDateTime(left, right ast.Expr, models [2]*model) (bool, error) {
	a, leftIdent := left.(*ast.Ident)
	b, rightIdent := right.(*ast.Ident)
	if !leftIdent || !rightIdent || a.Name != "DateTime" || b.Name != "DateTime" {
		return false, nil
	}
	for _, source := range models {
		underlying, ok := source.types["DateTime"].(*ast.Ident)
		if !ok || underlying.Name != "string" || !source.custom["DateTime"] {
			return false, fmt.Errorf("DateTime compatibility rule requires custom string types in both versions")
		}
	}
	return true, nil
}
