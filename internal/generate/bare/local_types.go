// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"strings"
)

type localTypeKey struct {
	version int // index into models, not the specification version number
	name    string
}

func (m *typedModel) localType(expr ast.Expr, version int) (string, error) {
	return renderType(expr, func(name string) (string, error) {
		source := m.models[version]
		definition := source.types[name]
		if definition == nil {
			return name, nil
		}
		if source.custom[name] {
			return fmt.Sprintf("v%d.%s", 20+version, name), nil
		}
		key := localTypeKey{version, name}
		if known := m.localTypes[key]; known != "" {
			return known, nil
		}

		localName := m.reserveLocalName(name, version)
		// Register before following children so recursive references reuse the name.
		m.localTypes[key] = localName
		body, err := m.localType(definition, version)
		if err != nil {
			return "", err
		}
		// Aliases must stay aliases: a defined copy of a custom type would drop its UnmarshalJSON.
		assignment := ""
		if source.aliases[name] {
			assignment = "= "
		}
		var out strings.Builder
		fmt.Fprintf(&out, "type %s %s%s\n\n", localName, assignment, body)
		for _, constant := range source.constants[name] {
			for i, originalName := range constant.Names {
				// Keep the enum constant's prefix aligned with a renamed type.
				constantName := originalName.Name
				if strings.HasPrefix(constantName, name) {
					constantName = localName + strings.TrimPrefix(constantName, name)
				}
				constantName = m.reserveLocalName(constantName, version)
				var value bytes.Buffer
				if err := format.Node(&value, token.NewFileSet(), constant.Values[i]); err != nil {
					return "", err
				}
				fmt.Fprintf(&out, "const %s %s = %s\n", constantName, localName, value.String())
			}
		}
		m.localDeclarations = append(m.localDeclarations, out.String())
		return localName, nil
	})
}

// Keep original names unless another generated type or constant already uses them.
func (m *typedModel) reserveLocalName(name string, version int) string {
	if m.names[name] {
		name = fmt.Sprintf("%s%d", name, 20+version)
	}
	m.names[name] = true
	return name
}
