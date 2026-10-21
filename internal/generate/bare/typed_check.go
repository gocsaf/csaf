// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"maps"
	"slices"
	"strconv"
)

type checkType struct {
	name   string
	shape  string
	elem   *checkType
	fields []checkField
	helper string
	shared *typedType
}

type checkField struct {
	name     string
	jsonName string
	typ      *checkType
	required bool
}

type checkTypeKey struct {
	expr    ast.Expr
	version int
}

type checkEmitter struct {
	out        bytes.Buffer
	model      *typedModel
	shared     map[*typedType]*checkType
	originals  map[checkTypeKey]*checkType
	structures []*checkType
	serial     int
}

func (e *checkEmitter) write(format string, args ...any) {
	fmt.Fprintf(&e.out, format, args...)
}

func (e *checkEmitter) sharedType(t *typedType) *checkType {
	if known := e.shared[t]; known != nil {
		return known
	}
	node := &checkType{name: typedName(t), shape: t.shape, shared: t}
	e.shared[t] = node
	switch t.shape {
	case "struct":
		node.helper = "check" + t.name
		e.structures = append(e.structures, node)
		for _, f := range t.fields {
			if f.common != nil {
				node.fields = append(node.fields, checkField{f.name, f.jsonName, e.sharedType(f.common), f.versions[0].required() && f.versions[1].required()})
			}
		}
	case "pointer", "slice":
		node.elem = e.sharedType(t.elem)
	}
	return node
}

func (e *checkEmitter) originalType(expr ast.Expr, version int) (*checkType, error) {
	key := checkTypeKey{expr, version}
	if known := e.originals[key]; known != nil {
		return known, nil
	}
	name, err := wireType(expr, 20+version, e.model.models[version])
	if err != nil {
		return nil, err
	}
	resolved := expr
	for {
		ident, ok := resolved.(*ast.Ident)
		if !ok || e.model.models[version].types[ident.Name] == nil {
			break
		}
		resolved = e.model.models[version].types[ident.Name]
	}
	node := &checkType{name: name}
	e.originals[key] = node
	switch t := resolved.(type) {
	case *ast.Ident:
		node.shape = t.Name
	case *ast.StarExpr:
		node.shape = "pointer"
		node.elem, err = e.originalType(t.X, version)
	case *ast.ArrayType:
		if t.Len != nil {
			return nil, fmt.Errorf("fixed arrays are unsupported in checks")
		}
		node.shape = "slice"
		node.elem, err = e.originalType(t.Elt, version)
	case *ast.MapType:
		node.shape = "map"
	case *ast.InterfaceType:
		node.shape = "interface"
	case *ast.StructType:
		node.shape = "struct"
		node.helper = fmt.Sprintf("checkVersion%dStruct%d", 20+version, len(e.structures))
		e.structures = append(e.structures, node)
		fields, fieldErr := structFields(t)
		if fieldErr != nil {
			return nil, fieldErr
		}
		for _, jsonName := range slices.Sorted(maps.Keys(fields)) {
			f := fields[jsonName]
			child, fieldErr := e.originalType(f.typ, version)
			if fieldErr != nil {
				return nil, fieldErr
			}
			node.fields = append(node.fields, checkField{f.goName, f.name, child, f.required()})
		}
	default:
		return nil, fmt.Errorf("unsupported check type %T", resolved)
	}
	return node, err
}

// presence is a deliberately simplified model check. In the reviewed CSAF
// schemas required strings exclude empty values through minLength, enum, pattern
// or asserted format constraints and all required arrays have minItems >= 1.
// Neither follows from required alone. Assumptions should be rechecked on schema
// updates.
func (e *checkEmitter) presence(value string, t *checkType, path string) {
	condition := ""
	switch t.shape {
	case "string", "v21.DateTime":
		condition = value + ` == ""`
	case "slice":
		condition = "len(" + value + ") == 0"
	case "pointer", "map", "interface":
		condition = value + " == nil"
	}
	if condition != "" {
		e.write("if %s { return fmt.Errorf(%q) }\n", condition, path+": required value is missing or empty")
	}
	if t.shape == "pointer" {
		// The nil check above returns before dereferencing a required pointer.
		e.presence("*("+value+")", t.elem, path)
	}
}

func (e *checkEmitter) contents(value string, t *checkType, path string) {
	switch t.shape {
	case "struct":
		e.write("if err := %s(&(%s), v); err != nil { return fmt.Errorf(\"%%s.%%w\", %s, err) }\n", t.helper, value, path)
	case "pointer", "slice":
		leaf := t.elem
		for leaf.shape == "pointer" || leaf.shape == "slice" {
			leaf = leaf.elem
		}
		// If it's not a struct, it's basically covered by the earlier presence checks already.
		if leaf.shape != "struct" {
			return
		}

		if t.shape == "pointer" {
			e.write("if %s != nil {\n", value)
			e.contents("*("+value+")", t.elem, path)
		} else {
			e.serial++
			index := fmt.Sprintf("index%d", e.serial)
			e.write("for %s := range %s {\n", index, value)
			e.contents("("+value+")["+index+"]", t.elem, fmt.Sprintf("fmt.Sprintf(\"%%s[%%d]\", %s, %s)", path, index))
		}
		e.write("}\n")
	}
}

func (e *checkEmitter) emitStruct(node *checkType) error {
	e.write("func %s(source *%s, v version) error {\n", node.helper, node.name)
	if t := node.shared; t != nil {
		has := [2]bool{t.details[0] != nil, t.details[1] != nil}
		if has[0] && has[1] {
			e.write("if source.%s != nil && source.%s != nil { return fmt.Errorf(\"both version details are present\") }\n", t.details[0].name, t.details[1].name)
		}
		needsSwitch := has[0] || has[1]
		// Check if field is required in one version but not the other.
		for _, f := range t.fields {
			if f.common != nil && f.versions[0].required() != f.versions[1].required() {
				needsSwitch = true
			}
		}

		if needsSwitch {
			e.write("switch v {\n")
			for i := range 2 {
				e.write("case version%d:\n", 20+i)
				if has[1-i] {
					e.write("if source.%s != nil { return fmt.Errorf(%q) }\n", t.details[1-i].name, fmt.Sprintf("version 2.%d details are present in version 2.%d", 1-i, i))
				}
				// Existing details identify the object's version, even when all
				// contained fields are optional. Their contents are checked later.
				if has[i] {
					e.write("if source.%s == nil { return fmt.Errorf(%q) }\n", t.details[i].name, fmt.Sprintf("version 2.%d details are missing", i))
				}
				// Check if field is required in one version but not the other and emit presence checks for the required version.
				for _, f := range t.fields {
					if f.common != nil && f.versions[i].required() && !f.versions[1-i].required() {
						e.presence("source."+f.name, e.sharedType(f.common), f.jsonName)
					}
				}
			}
			e.write("}\n")
		}
	}
	// Required check for shared fields
	for _, f := range node.fields {
		if f.required {
			e.presence("source."+f.name, f.typ, f.jsonName)
		}
	}

	for _, f := range node.fields {
		e.contents("source."+f.name, f.typ, strconv.Quote(f.jsonName))
	}

	if t := node.shared; t != nil {
		for _, detail := range t.details {
			if detail == nil {
				continue
			}
			d, err := e.detailsType(detail)
			if err != nil {
				return err
			}
			e.write("if source.%s != nil {\nif err := %s(source.%s, v); err != nil { return err }\n}\n", d.name, d.helper, d.name)
		}
	}
	e.write("return nil\n}\n")
	return nil
}

func (e *checkEmitter) detailsType(detail *typedDetails) (*checkType, error) {
	node := &checkType{name: detail.name, shape: "struct", helper: "check" + detail.name}
	for _, f := range detail.fields {
		original := f.versions[detail.version]
		child, err := e.originalType(original.typ, detail.version)
		if err != nil {
			return nil, err
		}
		node.fields = append(node.fields, checkField{f.name, f.jsonName, child, original.required()})
	}
	e.structures = append(e.structures, node)
	return node, nil
}

func (m *typedModel) emitCheck(packageName string) ([]byte, error) {
	e := &checkEmitter{model: m, shared: make(map[*typedType]*checkType), originals: make(map[checkTypeKey]*checkType)}
	root := m.structures[0]
	e.sharedType(root)
	versionField := map[string]string{"CSAF": "Document.CSAFVersion", "Provider": "MetadataVersion", "Aggregator": "AggregatorVersion"}[root.name]
	if versionField == "" {
		return nil, fmt.Errorf("no check version field for %s", root.name)
	}
	e.write("// Checks version consistency and required model values.  It rejects missing\n// required pointers, empty required strings and empty required slices. It does\n// not validate schema formats, enums, exact lengths or conditional constraints.\n// Zero-valued numbers and booleans are accepted.\n")
	e.write("func (source *%s) Check() error {\nif source == nil { return fmt.Errorf(\"nil document\") }\nvar v version\nswitch source.%s {\ncase \"2.0\": v = version20\ncase \"2.1\": v = version21\ndefault: return fmt.Errorf(\"unsupported version %%q\", source.%s)\n}\nreturn check%s(source,v)\n}\n", root.name, versionField, versionField, root.name)
	for i := 0; i < len(e.structures); i++ {
		if err := e.emitStruct(e.structures[i]); err != nil {
			return nil, err
		}
	}
	return typedSource(packageName, e.out.String())
}
