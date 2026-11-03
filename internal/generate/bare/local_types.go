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
	"reflect"
	"strconv"
	"strings"
)

type localTypeKey struct {
	version int // index into models, not the specification version number
	name    string
}

type localConstant struct {
	name     string
	value    string
	versions [2]bool // versions in which the value is valid
}

func (m *typedModel) localType(expr ast.Expr, version int) (*typedType, error) {
	if known := m.localExpressions[version][expr]; known != nil {
		return known, nil
	}
	node, err := m.buildLocalType(expr, version)
	if err != nil {
		return nil, err
	}
	m.localExpressions[version][expr] = node
	return node, nil
}

func (m *typedModel) buildLocalType(expr ast.Expr, version int) (*typedType, error) {
	source := m.models[version]
	switch t := expr.(type) {
	case *ast.Ident:
		definition := source.types[t.Name]
		if definition == nil {
			return &typedType{shape: t.Name}, nil
		}
		if t.Name == "DateTime" {
			return &typedType{shape: dateTimeType}, nil
		}
		if source.custom[t.Name] {
			return &typedType{shape: fmt.Sprintf("v%d.%s", 20+version, t.Name)}, nil
		}
		// Reuse shared named types. Enums check their values per version.
		if shared := m.namedByVersion[version][t.Name]; shared != nil {
			// The checks still need the prepared parts of the definition.
			if _, err := m.localType(definition, version); err != nil {
				return nil, err
			}
			return shared, nil
		}
		key := localTypeKey{version, t.Name}
		if known := m.localTypes[key]; known != nil {
			return known, nil
		}
		node := &typedType{shape: "named", name: m.reserveLocalName(t.Name, version), alias: source.aliases[t.Name]}
		// Register before following children so recursive references reuse the node.
		m.localTypes[key] = node
		var err error
		node.elem, err = m.localType(definition, version)
		if err != nil {
			return nil, err
		}
		for _, constant := range source.constants[t.Name] {
			for i, originalName := range constant.Names {
				name := originalName.Name
				if strings.HasPrefix(name, t.Name) {
					name = node.name + strings.TrimPrefix(name, t.Name)
				}
				var value bytes.Buffer
				if err := format.Node(&value, token.NewFileSet(), constant.Values[i]); err != nil {
					return nil, err
				}
				constant := localConstant{name: m.reserveLocalName(name, version), value: value.String()}
				constant.versions[version] = true
				node.constants = append(node.constants, constant)
			}
		}
		m.localDeclarations = append(m.localDeclarations, node)
		return node, nil
	case *ast.StarExpr:
		elem, err := m.localType(t.X, version)
		return &typedType{shape: "pointer", elem: elem}, err
	case *ast.ArrayType:
		if t.Len != nil {
			return nil, fmt.Errorf("fixed arrays are unsupported")
		}
		elem, err := m.localType(t.Elt, version)
		return &typedType{shape: "slice", elem: elem}, err
	case *ast.MapType:
		if key, ok := t.Key.(*ast.Ident); !ok || key.Name != "string" {
			return nil, fmt.Errorf("expected string map key")
		}
		elem, err := m.localType(t.Value, version)
		return &typedType{shape: "map", elem: elem}, err
	case *ast.InterfaceType:
		if len(t.Methods.List) != 0 {
			return nil, fmt.Errorf("anonymous non-empty interface")
		}
		return &typedType{shape: "any"}, nil
	case *ast.StructType:
		node := &typedType{shape: "struct"}
		fields, err := structFields(t)
		if err != nil {
			return nil, err
		}
		for _, original := range t.Fields.List {
			tag, err := strconv.Unquote(original.Tag.Value)
			if err != nil {
				return nil, err
			}
			jsonName, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
			f, exists := fields[jsonName]
			if !exists {
				continue
			}
			typ, err := m.localType(f.typ, version)
			if err != nil {
				return nil, err
			}
			field := typedField{name: f.goName, jsonName: jsonName, common: typ, tag: original.Tag.Value}
			field.versions[version] = f
			node.fields = append(node.fields, field)
		}
		return node, nil
	default:
		return nil, fmt.Errorf("unsupported version-specific type %T", expr)
	}
}

// Keep original names unless another generated type already uses them.
func (m *typedModel) reserveLocalName(name string, version int) string {
	if m.names[name] {
		name = fmt.Sprintf("%s%d", name, 20+version)
	}
	m.names[name] = true
	return name
}
