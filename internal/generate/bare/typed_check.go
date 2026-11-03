// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"maps"
	"slices"
	"strings"
)

type checkType struct {
	name   string
	shape  string
	elem   *checkType
	fields []checkField
	shared *typedType
	enum   bool // the type has a validIn method
}

type checkField struct {
	name     string
	jsonName string
	typ      *checkType
	required bool
}

type checkTypeKey struct {
	expr             ast.Expr
	version          int
	keepVersionTypes bool
}

type checkEmitter struct {
	out        bytes.Buffer
	model      *typedModel
	shared     map[*typedType]*checkType
	originals  map[checkTypeKey]*checkType
	locals     map[*typedType]*checkType // one check per local type, methods must be unique
	structures []*checkType
	loopDepth  int
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
	if t.replacement {
		node.shape = "replacement"
		return node
	}
	switch t.shape {
	case "struct":
		e.structures = append(e.structures, node)
		for _, f := range t.fields {
			if f.common != nil {
				node.fields = append(node.fields, checkField{f.name, f.jsonName, e.sharedType(f.common), f.versions[0].required() && f.versions[1].required()})
			}
		}
	case "pointer", "slice":
		node.elem = e.sharedType(t.elem)
	case "named":
		// Checks use the shape of the definition.
		definition := e.sharedType(t.elem)
		node.shape = definition.shape
		node.elem = definition.elem
		node.enum = len(t.constants) > 0
	}
	return node
}

// originalType resolves a type expression to its original definition, following type aliases and keeping track of whether any custom decoders are involved. It returns a checkType representing the resolved type, or an error if the type cannot be resolved.
func (e *checkEmitter) originalType(expr ast.Expr, version int, keepVersionTypes bool) (*checkType, error) {
	resolved := expr
	for {
		ident, ok := resolved.(*ast.Ident)
		if !ok || e.model.models[version].types[ident.Name] == nil {
			break
		}
		// Keep types with custom decoders.
		if e.model.models[version].custom[ident.Name] {
			keepVersionTypes = true
		}
		resolved = e.model.models[version].types[ident.Name]
	}
	key := checkTypeKey{expr, version, keepVersionTypes}
	if known := e.originals[key]; known != nil {
		return known, nil
	}
	var name string
	var err error
	var local *typedType
	if keepVersionTypes {
		name, err = wireType(expr, 20+version, e.model.models[version])
	} else {
		local = e.model.localExpressions[version][expr]
		name = typedName(local)
		if known := e.locals[local]; known != nil && local.shape == "named" {
			return known, nil
		}
	}
	if err != nil {
		return nil, err
	}
	node := &checkType{name: name}
	if local != nil && local.shape == "named" && len(local.constants) > 0 {
		node.enum = true
	}
	e.originals[key] = node
	if local != nil && local.shape == "named" {
		e.locals[local] = node
	}
	switch t := resolved.(type) {
	case *ast.Ident:
		node.shape = t.Name
	case *ast.StarExpr:
		node.shape = "pointer"
		node.elem, err = e.originalType(t.X, version, keepVersionTypes)
	case *ast.ArrayType:
		if t.Len != nil {
			return nil, errors.New("fixed arrays are unsupported in checks")
		}
		node.shape = "slice"
		node.elem, err = e.originalType(t.Elt, version, keepVersionTypes)
	case *ast.MapType:
		node.shape = "map"
	case *ast.InterfaceType:
		node.shape = "interface"
	case *ast.StructType:
		if keepVersionTypes {
			node.shape = "external"
			return node, nil
		}
		node.shape = "struct"
		if local == nil || local.shape != "named" {
			return nil, fmt.Errorf("check method requires a named local struct: %s", name)
		}
		e.structures = append(e.structures, node)
		fields, fieldErr := structFields(t)
		if fieldErr != nil {
			return nil, fieldErr
		}
		var localFields map[string]*typedField
		if local != nil {
			structure, _, _ := namedStruct(local)
			localFields, fieldErr = typedFields(structure)
			if fieldErr != nil {
				return nil, fieldErr
			}
		}
		for _, jsonName := range slices.Sorted(maps.Keys(fields)) {
			f := fields[jsonName]
			if replacement := localFields[jsonName]; replacement != nil {
				f.goName = replacement.name
				if replacement.common.replacement {
					child := &checkType{name: typedName(replacement.common), shape: "replacement"}
					node.fields = append(node.fields, checkField{f.goName, f.name, child, false})
					continue
				}
			}
			child, fieldErr := e.originalType(f.typ, version, keepVersionTypes)
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

type presenceCheck struct {
	condition string
	message   string
}

// presenceChecks implements a deliberately simplified model check. In the reviewed CSAF
// schemas required strings exclude empty values through minLength, enum, pattern
// or asserted format constraints and all required arrays have minItems >= 1.
// Neither follows from required alone. Assumptions should be rechecked on schema
// updates.
func presenceChecks(value string, t *checkType, path string) []presenceCheck {
	condition := ""
	switch t.shape {
	case "string", dateTimeType:
		condition = value + ` == ""`
	case "slice":
		condition = "len(" + value + ") == 0"
	case "pointer", "map", "interface":
		condition = value + " == nil"
	}
	var checks []presenceCheck
	if condition != "" {
		checks = append(checks, presenceCheck{condition, path + ": required value is missing or empty"})
	}
	if t.shape == "pointer" {
		// Check nil before dereferencing a required pointer.
		checks = append(checks, presenceChecks("*"+value, t.elem, path)...)
	}
	return checks
}

func (e *checkEmitter) presence(value string, t *checkType, path string) {
	for _, check := range presenceChecks(value, t, path) {
		e.write("if %s { return errors.New(%q) }\n", check.condition, check.message)
	}
}

func (e *checkEmitter) contents(value string, t *checkType, path errorPath) {
	if t.enum {
		// Empty values are absent. Required values are already checked for presence.
		receiver := value
		if strings.HasPrefix(receiver, "*") {
			receiver = "(" + receiver + ")"
		}
		args := append(slices.Clone(path.indices), value)
		e.write("if %s != \"\" && !%s.validIn(v) { return fmt.Errorf(%q, %s) }\n", value, receiver, path.format+": invalid value %q", strings.Join(args, ", "))
		return
	}
	switch t.shape {
	case "struct", "external":
		// A pointer receiver works on the field itself, so drop a dereference.
		receiver := strings.TrimPrefix(value, "*")
		if t.shape == "external" {
			e.write("if err := %s.Check(); err != nil { return %s }\n", receiver, path.wrap("."))
		} else {
			e.write("if err := %s.Check(v); err != nil { return %s }\n", receiver, path.wrap("."))
		}
	case "replacement":
		// Handwritten replacement types provide their own Check(v version) error method.
		// Their errors start with "." or "[" so the path continues without a separator.
		e.write("if err := %s.Check(v); err != nil { return %s }\n", value, path.wrap(""))
	case "pointer", "slice":
		leaf := t.elem
		for leaf.shape == "pointer" || leaf.shape == "slice" {
			leaf = leaf.elem
		}
		// If it's not a struct or enum, it's basically covered by the earlier presence checks already.
		if leaf.shape != "struct" && leaf.shape != "external" && !leaf.enum {
			return
		}

		if t.shape == "pointer" {
			e.write("if %s != nil {\n", value)
			e.contents("*"+value, t.elem, path)
		} else {
			index := loopIndex(e.loopDepth)
			e.loopDepth++
			e.write("for %s := range %s {\n", index, value)
			e.contents(indexExpression(value, index), t.elem, path.indexed(index))
			e.loopDepth--
		}
		e.write("}\n")
	}
}

func (e *checkEmitter) emitStruct(node *checkType) error {
	if node.shared == e.model.structures[0] {
		versionField, err := sharedVersionAccess(node.shared, e.model.versionPath)
		if err != nil {
			return err
		}
		e.write("func (source *%s) Check() error {\nif source == nil { return errors.New(\"nil document\") }\nvar v version\nswitch source.%s {\ncase \"2.0\": v = version20\ncase \"2.1\": v = version21\ndefault: return fmt.Errorf(\"unsupported version %%q\", source.%s)\n}\n", node.name, versionField, versionField)
	} else {
		e.write("func (source *%s) Check(v version) error {\n", node.name)
	}
	if t := node.shared; t != nil {
		has := [2]bool{t.details[0] != nil, t.details[1] != nil}
		if has[0] && has[1] {
			e.write("if source.%s != nil && source.%s != nil { return errors.New(\"both version details are present\") }\n", t.details[0].privateName(), t.details[1].privateName())
		}
		var versionChecks [2][]presenceCheck
		for i := range 2 {
			if has[1-i] {
				versionChecks[i] = append(versionChecks[i], presenceCheck{
					"source." + t.details[1-i].privateName() + " != nil",
					fmt.Sprintf("version 2.%d details are present in version 2.%d", 1-i, i),
				})
			}
			// Details identify the version even if all their fields are optional.
			if has[i] {
				versionChecks[i] = append(versionChecks[i], presenceCheck{
					"source." + t.details[i].privateName() + " == nil",
					fmt.Sprintf("version 2.%d details are missing", i),
				})
			}
			for _, f := range t.fields {
				if f.common != nil && f.versions[i].required() && !f.versions[1-i].required() {
					versionChecks[i] = append(versionChecks[i], presenceChecks("source."+f.name, e.sharedType(f.common), f.jsonName)...)
				}
			}
		}
		if len(versionChecks[0]) > 0 || len(versionChecks[1]) > 0 {
			// Fold single-condition branches into the case.
			simple := len(versionChecks[0]) <= 1 && len(versionChecks[1]) <= 1
			if simple {
				e.write("switch {\n")
			} else {
				e.write("switch v {\n")
			}
			for i, checks := range versionChecks {
				if !simple && len(checks) > 0 {
					e.write("case version%d:\n", 20+i)
				}
				for _, check := range checks {
					if simple {
						e.write("case v == version%d && %s: return errors.New(%q)\n", 20+i, check.condition, check.message)
					} else {
						e.write("if %s { return errors.New(%q) }\n", check.condition, check.message)
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
		e.contents("source."+f.name, f.typ, fieldErrorPath(f.jsonName))
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
			e.write("if source.%s != nil {\nif err := source.%s.Check(v); err != nil { return err }\n}\n", d.name, d.name)
		}
	}
	e.write("return nil\n}\n\n")
	return nil
}

func (e *checkEmitter) detailsType(detail *typedDetails) (*checkType, error) {
	node := &checkType{name: detail.privateName(), shape: "struct"}
	for _, f := range detail.fields {
		if f.local.replacement {
			child := &checkType{name: typedName(f.local), shape: "replacement"}
			node.fields = append(node.fields, checkField{f.name, f.jsonName, child, false})
			continue
		}
		original := f.versions[detail.version]
		child, err := e.originalType(original.typ, detail.version, false)
		if err != nil {
			return nil, err
		}
		node.fields = append(node.fields, checkField{f.name, f.jsonName, child, original.required()})
	}
	e.structures = append(e.structures, node)
	return node, nil
}

func (m *typedModel) emitCheck(packageName string) ([]byte, error) {
	e := &checkEmitter{model: m, shared: make(map[*typedType]*checkType), originals: make(map[checkTypeKey]*checkType), locals: make(map[*typedType]*checkType)}
	root := m.structures[0]
	e.sharedType(root)
	e.write("// Checks version consistency and required model values. It rejects missing\n// required pointers, empty required strings and empty required slices and\n// enum values that are not valid in the document version. Types taken directly\n// from the version packages must provide their own Check() error method.\n// Local checks do not validate schema formats, exact lengths or conditional\n// constraints. Zero-valued numbers and booleans are accepted.\n")
	for i := 0; i < len(e.structures); i++ {
		if err := e.emitStruct(e.structures[i]); err != nil {
			return nil, err
		}
	}
	return typedSource(packageName, e.out.String())
}
