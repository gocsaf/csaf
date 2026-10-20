// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"go/ast"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// When true, fields with different omitempty settings or outer pointer/value
// shapes remain in version details instead of becoming shared optional fields.
const separateOptionalityDifferences = true

// typedType describes a common representation
type typedType struct {
	shape  string       // primitive, "pointer", "slice", "struct"
	name   string       // struct name, if shape is "struct"
	elem   *typedType   // element type, if shape is "pointer" or "slice"
	fields []typedField // fields, if shape is "struct"
	bare   *match       // bare match, if any
}

type typedField struct {
	name     string       // Go name of the field
	jsonName string       // JSON name of the field
	common   *typedType   // nil means version-specific / differs in the versions / details only
	versions [2]jsonField // original types and presence, retained for typed output
	bare     *fieldMatch  // bare match, if any
}

type typedModel struct {
	models     [2]*model // left and right models
	cache      map[typePair]*typedType
	structures []*typedType // all structs in the order they were generated
	names      map[string]bool
}

func newTypedModel(left, right *model, rootName string, root *match) (*typedModel, error) {
	m := &typedModel{models: [2]*model{left, right}, cache: make(map[typePair]*typedType), names: make(map[string]bool)}
	if _, err := m.common(left.types[rootName], right.types[rootName], rootName, root); err != nil {
		return nil, err
	}
	return m, nil
}

// common determines a shared type from left and right. The optional bare result
// is used only to reuse names and field mappings from bare generation
func (m *typedModel) common(left, right ast.Expr, name string, bare *match) (*typedType, error) {
	if left == nil || right == nil {
		return nil, nil
	}

	// DateTime compatibility rule
	if a, ok := left.(*ast.Ident); ok && a.Name == "DateTime" {
		if b, ok := right.(*ast.Ident); ok && b.Name == "DateTime" {
			for _, source := range m.models {
				underlying, ok := source.types["DateTime"].(*ast.Ident)
				if !ok || underlying.Name != "string" || !source.custom["DateTime"] {
					return nil, fmt.Errorf("DateTime compatibility rule requires custom string types in both versions")
				}
			}
			return &typedType{shape: "v21.DateTime"}, nil
		}
	}
	left, leftRaw := m.models[0].resolve(left)
	right, rightRaw := m.models[1].resolve(right)

	// type with their own unmarshalJSON should be handled specially (like DateTime above)
	if leftRaw || rightRaw {
		return nil, nil
	}

	pair := typePair{left, right}
	if cached := m.cache[pair]; cached != nil {
		return cached, nil
	}

	node := &typedType{bare: bare}
	switch a := left.(type) {
	case *ast.StarExpr:
		b := right
		if pointer, ok := b.(*ast.StarExpr); ok { // check if right side is also a pointer
			b = pointer.X
		}

		// bare is type with pointer
		// child/bare.elem is the type of the pointer
		var child *match
		if bare != nil && !bare.raw && bare.shape == "pointer" {
			child = bare.elem
		}
		elem, err := m.common(a.X, b, name, child)
		if err != nil || elem == nil {
			return nil, err
		}
		node.shape, node.elem = "pointer", elem
	case *ast.ArrayType:
		b, ok := right.(*ast.ArrayType) // check if right side is also an array
		if !ok || a.Len != nil || b.Len != nil {
			return nil, nil
		}
		var child *match
		if bare != nil && !bare.raw && bare.shape == "slice" {
			child = bare.elem
		}
		elem, err := m.common(a.Elt, b.Elt, name+"Elem", child)
		if err != nil || elem == nil {
			return nil, err
		}
		node.shape, node.elem = "slice", elem
	case *ast.StructType:
		if pointer, ok := right.(*ast.StarExpr); ok {
			return m.common(&ast.StarExpr{X: left}, pointer, name, bare)
		}
		b, ok := right.(*ast.StructType) // check if right side is also a struct
		if !ok {
			return nil, nil
		}
		node.shape = "struct"
		if bare != nil && !bare.raw {
			name = bare.name
		}
		for m.names[name] {
			name += "Type"
		}
		node.name = name
		m.names[name] = true
		m.cache[pair] = node // recursive product branches refer back to this node
		m.structures = append(m.structures, node)
		if err := m.fields(node, a, b); err != nil {
			return nil, err
		}
	case *ast.Ident:
		if pointer, ok := right.(*ast.StarExpr); ok {
			return m.common(&ast.StarExpr{X: left}, pointer, name, bare)
		}
		b, ok := right.(*ast.Ident) // check if right side is also an identifier
		if !ok || a.Name != b.Name || !primitive(a.Name) {
			return nil, nil
		}
		node.shape = a.Name
	default:
		return nil, nil
	}
	m.cache[pair] = node
	return node, nil
}

func (m *typedModel) fields(node *typedType, left, right *ast.StructType) error {
	a, err := structFields(left)
	if err != nil {
		return err
	}
	b, err := structFields(right)
	if err != nil {
		return err
	}
	names := slices.Sorted(maps.Keys(a))
	for name := range b {
		if _, exists := a[name]; !exists {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		first, second := a[name], b[name]
		goName := first.goName
		if goName == "" {
			goName = second.goName
		}
		field := typedField{name: goName, jsonName: name, versions: [2]jsonField{first, second}}
		// Match this field to its bare counterpart by JSON name
		if node.bare != nil && !node.bare.raw {
			for i := range node.bare.fields {
				if f := &node.bare.fields[i]; f.jsonName == name {
					field.bare = f
					field.name = f.goName
					break
				}
			}
		}
		if separateOptionalityDifferences && optionalityDiffers(field.versions, m.models) {
			node.fields = append(node.fields, field)
			continue
		}
		var bare *match
		if field.bare != nil {
			bare = field.bare.typ
		}

		// if the field is a struct as well, this will recursively call common()/fields() to generate the nested struct type
		field.common, err = m.common(field.versions[0].typ, field.versions[1].typ, node.name+field.name, bare)
		if err != nil {
			return err
		}
		node.fields = append(node.fields, field)
	}
	return nil
}

func optionalityDiffers(fields [2]jsonField, models [2]*model) bool {
	if fields[0].typ == nil || fields[1].typ == nil {
		return false // Version-only fields already belong in details.
	}
	if fields[0].omitEmpty != fields[1].omitEmpty {
		return true
	}
	left, _ := models[0].resolve(fields[0].typ)
	right, _ := models[1].resolve(fields[1].typ)
	_, leftPointer := left.(*ast.StarExpr)
	_, rightPointer := right.(*ast.StarExpr)
	return leftPointer != rightPointer
}

func typedName(t *typedType) string {
	switch t.shape {
	case "pointer":
		return "*" + typedName(t.elem)
	case "slice":
		return "[]" + typedName(t.elem)
	case "struct":
		return t.name
	default:
		return t.shape
	}
}

func wireType(expr ast.Expr, version int, m *model) (string, error) {
	child := func(expr ast.Expr) (string, error) { return wireType(expr, version, m) }
	switch t := expr.(type) {
	case *ast.Ident:
		if m.types[t.Name] != nil {
			return fmt.Sprintf("v%d.%s", version, t.Name), nil
		}
		return t.Name, nil
	case *ast.StarExpr:
		value, err := child(t.X)
		return "*" + value, err
	case *ast.ArrayType:
		if t.Len != nil {
			return "", fmt.Errorf("fixed arrays are unsupported")
		}
		value, err := child(t.Elt)
		return "[]" + value, err
	case *ast.MapType:
		key, err := child(t.Key)
		if err != nil {
			return "", err
		}
		value, err := child(t.Value)
		return "map[" + key + "]" + value, err
	case *ast.InterfaceType:
		if len(t.Methods.List) != 0 {
			return "", fmt.Errorf("anonymous non-empty interface")
		}
		return "any", nil
	case *ast.StructType:
		var out strings.Builder
		out.WriteString("struct {\n")
		for _, f := range t.Fields.List {
			typ, err := child(f.Type)
			if err != nil {
				return "", err
			}
			if len(f.Names) != 1 {
				return "", fmt.Errorf("expected named schema field")
			}
			fmt.Fprintf(&out, "%s %s", f.Names[0].Name, typ)
			if f.Tag != nil {
				fmt.Fprintf(&out, " %s", f.Tag.Value)
			}
			out.WriteString("\n")
		}
		out.WriteString("}")
		return out.String(), nil
	default:
		return "", fmt.Errorf("unsupported version-specific type %T", expr)
	}
}

func jsonTag(name string, optional bool) string {
	if optional {
		name += ",omitempty"
	}
	return "`json:" + strconv.Quote(name) + "`"
}

func details(node *typedType, version int) []typedField {
	var result []typedField
	for _, f := range node.fields {
		if f.common == nil && f.versions[version].typ != nil {
			result = append(result, f)
		}
	}
	return result
}
