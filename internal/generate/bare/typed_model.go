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
	"maps"
	"slices"
	"strconv"
	"strings"
)

// typedType describes a shared type or a copied version-detail type.
type typedType struct {
	shape       string           // primitive, "pointer", "slice", "map", "struct", "named"
	name        string           // declaration name for struct and named types
	elem        *typedType       // element or underlying type of pointer, slice, map and named nodes
	fields      []typedField     // fields, if shape is "struct"
	bare        *match           // bare match, if any
	details     [2]*typedDetails // version-specific structs, nil when absent
	alias       bool
	constants   []localConstant
	sharedEnum  bool // enum with the constants of both versions
	replacement bool // supplied by handwritten types
}

// typedDetails describes a version detail struct once for all emitters.
// version indexes the original v20/v21 model and field definitions.
type typedDetails struct {
	name    string
	version int
	fields  []typedField
}

// Lowercases the leading run of ASCII uppercase letters, keeping the last
// uppercase letter if it starts a word followed by lowercase letters.
// The first letter is always lowercased, so Provider becomes provider and
// CSAFDocument becomes csafDocument.
func (d *typedDetails) privateName() string {
	end := 0
	for end < len(d.name) && d.name[end] >= 'A' && d.name[end] <= 'Z' {
		if end > 0 && end+1 < len(d.name) && d.name[end+1] >= 'a' && d.name[end+1] <= 'z' {
			break
		}
		end++
	}
	return strings.ToLower(d.name[:end]) + d.name[end:]
}

type typedField struct {
	name     string       // Go name of the field
	jsonName string       // JSON name of the field
	common   *typedType   // nil means version-specific / differs in the versions / details only, ohterwise the shared type
	versions [2]jsonField // original types and presence, retained for typed output
	bare     *fieldMatch  // bare match, if any
	local    *typedType   // prepared type of a version-specific detail field
	tag      string       // original tags of a copied local field
}

// returns the type of the field.
// (`type` is used by Go)
func (f *typedField) typ() *typedType {
	if f.local != nil {
		return f.local
	}
	return f.common
}

type typedModel struct {
	versionPath string
	models      [2]*model // left and right models
	cache       map[typePair]*typedType
	structures  []*typedType // shared structs in generation order. Each owns its details
	names       map[string]bool

	localTypes        map[localTypeKey]*typedType // source version/name -> local type
	localDeclarations []*typedType
	localExpressions  [2]map[ast.Expr]*typedType // source expressions -> prepared nodes used by checks

	namedTypes     map[string]*typedType    // "left|right" type names -> shared named type
	namedByVersion [2]map[string]*typedType // version type name -> shared named type, reused by details
}

func newTypedModel(left, right *model, rootName string, root *match) (*typedModel, error) {
	m := &typedModel{
		versionPath: roots[rootName].versionPath,
		models:      [2]*model{left, right}, cache: make(map[typePair]*typedType),
		names: make(map[string]bool), localTypes: make(map[localTypeKey]*typedType),
		localExpressions: [2]map[ast.Expr]*typedType{make(map[ast.Expr]*typedType), make(map[ast.Expr]*typedType)},
		namedTypes:       make(map[string]*typedType), namedByVersion: [2]map[string]*typedType{make(map[string]*typedType), make(map[string]*typedType)},
	}
	if _, err := m.common(left.types[rootName], right.types[rootName], rootName, root); err != nil {
		return nil, err
	}
	for _, node := range m.structures {
		for version := range 2 {
			var fields []typedField
			for _, f := range node.fields {
				if f.common == nil && f.versions[version].typ != nil {
					fields = append(fields, f)
				}
			}
			if len(fields) > 0 {
				node.details[version] = &typedDetails{
					name:    fmt.Sprintf("%s%dDetails", node.name, 20+version),
					version: version,
					fields:  fields,
				}
			}
		}
	}
	// Prepare local types for version-specific fields. This is done after the common() pass to ensure that all shared types are already known.
	for _, node := range m.structures {
		for _, detail := range node.details {
			if detail == nil {
				continue
			}
			for i := range detail.fields {
				field := &detail.fields[i]
				var err error
				field.local, err = m.localType(field.versions[detail.version].typ, detail.version)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return m, nil
}

// common determines a shared type from left and right. The optional bare result
// is used only to reuse names and field mappings from bare generation
func (m *typedModel) common(left, right ast.Expr, name string, bare *match) (*typedType, error) {
	if left == nil || right == nil {
		return nil, nil
	}
	// Keep custom type names intact until the contained types are compared.
	if a, ok := left.(*ast.StarExpr); ok {
		if _, rightPointer := right.(*ast.StarExpr); !rightPointer {
			return m.common(a, &ast.StarExpr{X: right}, name, bare)
		}
	} else if b, ok := right.(*ast.StarExpr); ok {
		return m.common(&ast.StarExpr{X: left}, b, name, bare)
	}

	if compatible, err := compatibleDateTime(left, right, m.models); err != nil {
		return nil, err
	} else if compatible {
		return &typedType{shape: "v21.DateTime"}, nil
	}
	// Handle named types that exist in both versions.
	// "Enums" get one type with the constants of both versions.
	// Other named types are only shared if name and definition are equal.
	if named, err := m.sharedNamed(left, right, bare); named != nil || err != nil {
		return named, err
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

// sharedNamed keeps named types that exist in both versions.
// "Enums" get one type with the constants of both versions.
// Other named types are only shared if name and definition are equal.
// Left and right are assumed to be from the same path.
func (m *typedModel) sharedNamed(left, right ast.Expr, bare *match) (*typedType, error) {
	a, ok := left.(*ast.Ident)
	if !ok {
		return nil, nil
	}
	b, ok := right.(*ast.Ident)
	if !ok {
		return nil, nil
	}
	definitionA := m.models[0].types[a.Name]
	definitionB := m.models[1].types[b.Name]
	if definitionA == nil || definitionB == nil || m.models[0].custom[a.Name] || m.models[1].custom[b.Name] {
		return nil, nil
	}
	key := a.Name + "|" + b.Name
	if known := m.namedTypes[key]; known != nil {
		return known, nil
	}

	constantsA := m.models[0].constants[a.Name]
	constantsB := m.models[1].constants[b.Name]
	isEnum := len(constantsA) > 0 && len(constantsB) > 0
	if !isEnum {
		// An enum on only one side does not happen in our schemas.
		if len(constantsA) > 0 || len(constantsB) > 0 || a.Name != b.Name {
			return nil, nil
		}
		// Merge only if both definitions are primitive or slices of primitives (not structs).
		if !primitiveLeaf(definitionA, m.models[0]) || !primitiveLeaf(definitionB, m.models[1]) {
			return nil, nil
		}
		keepName := func(name string) (string, error) { return name, nil }
		textA, err := renderType(definitionA, keepName)
		if err != nil {
			return nil, err
		}
		textB, err := renderType(definitionB, keepName)
		if err != nil {
			return nil, err
		}
		if textA != textB {
			return nil, nil
		}
	}

	name := b.Name
	for m.names[name] {
		name += "Type"
	}
	m.names[name] = true
	node := &typedType{shape: "named", name: name}
	m.namedTypes[key] = node

	if isEnum {
		baseA, _ := m.models[0].resolve(a)
		baseB, _ := m.models[1].resolve(b)
		identA, okA := baseA.(*ast.Ident)
		identB, okB := baseB.(*ast.Ident)
		if !okA || !okB || identA.Name != identB.Name {
			return nil, fmt.Errorf("enum %s has different base types", name)
		}
		node.elem = &typedType{shape: identA.Name}
		node.sharedEnum = true
		if err := m.mergeConstants(node, [2]string{a.Name, b.Name}, [2][]*ast.ValueSpec{constantsA, constantsB}); err != nil {
			return nil, err
		}
	} else {
		elem, err := m.common(definitionA, definitionB, name, bare)
		if err != nil {
			return nil, err
		}
		if elem == nil {
			return nil, fmt.Errorf("named type %s has no common definition", name)
		}
		node.elem = elem
	}
	m.namedByVersion[0][a.Name] = node
	m.namedByVersion[1][b.Name] = node
	m.localDeclarations = append(m.localDeclarations, node)
	return node, nil
}

// primitiveLeaf reports whether expr is a primitive or a slice of primitives.
func primitiveLeaf(expr ast.Expr, m *model) bool {
	for {
		switch t := expr.(type) {
		case *ast.Ident:
			if primitive(t.Name) {
				return true
			}
			if m.types[t.Name] == nil || m.custom[t.Name] {
				return false
			}
			expr = m.types[t.Name]
		case *ast.ArrayType:
			expr = t.Elt
		default:
			return false
		}
	}
}

// mergeConstants adds the constants of both versions to node.
// Constants are matched by value.
func (m *typedModel) mergeConstants(node *typedType, typeNames [2]string, constants [2][]*ast.ValueSpec) error {
	byValue := make(map[string]int)
	for version := range 2 {
		for _, spec := range constants[version] {
			for i, ident := range spec.Names {
				var value bytes.Buffer
				if err := format.Node(&value, token.NewFileSet(), spec.Values[i]); err != nil {
					return err
				}
				constantName := node.name + strings.TrimPrefix(ident.Name, typeNames[version])
				if index, ok := byValue[value.String()]; ok {
					if node.constants[index].name != constantName {
						return fmt.Errorf("value %s of %s has different constant names", value.String(), node.name)
					}
					node.constants[index].versions[version] = true
					continue
				}
				if m.names[constantName] {
					return fmt.Errorf("constant name %s is already used", constantName)
				}
				m.names[constantName] = true
				byValue[value.String()] = len(node.constants)
				constant := localConstant{name: constantName, value: value.String()}
				constant.versions[version] = true
				node.constants = append(node.constants, constant)
			}
		}
	}
	slices.SortFunc(node.constants, func(x, y localConstant) int { return strings.Compare(x.name, y.name) })
	return nil
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

func containsStruct(t *typedType) bool {
	for t.shape == "pointer" || t.shape == "slice" {
		t = t.elem
	}
	return t.shape == "struct"
}

func typedName(t *typedType) string {
	switch t.shape {
	case "pointer":
		return "*" + typedName(t.elem)
	case "slice":
		return "[]" + typedName(t.elem)
	case "named":
		return t.name
	case "map":
		return "map[string]" + typedName(t.elem)
	case "struct":
		if t.name != "" {
			return t.name
		}
		var out strings.Builder
		out.WriteString("struct {\n")
		for _, f := range t.fields {
			fmt.Fprintf(&out, "%s %s %s\n", f.name, typedName(f.common), f.tag)
		}
		out.WriteString("}")
		return out.String()
	default:
		return t.shape
	}
}

func wireType(expr ast.Expr, version int, m *model) (string, error) {
	return renderType(expr, func(name string) (string, error) {
		if m.types[name] != nil {
			return fmt.Sprintf("v%d.%s", version, name), nil
		}
		return name, nil
	})
}

func renderType(expr ast.Expr, namedType func(string) (string, error)) (string, error) {
	child := func(expr ast.Expr) (string, error) { return renderType(expr, namedType) }
	switch t := expr.(type) {
	case *ast.Ident:
		return namedType(t.Name)
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
