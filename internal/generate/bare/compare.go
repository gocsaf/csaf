// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"go/ast"
	"maps"
	"slices"
)

type match struct {
	raw    bool
	shape  string       // primitive, "pointer", "slice", "struct"
	name   string       // struct name, if shape is "struct"
	elem   *match       // element type, if shape is "pointer" or "slice"
	fields []fieldMatch // fields, if shape is "struct"
}

type fieldMatch struct {
	jsonName  string       // JSON name of the field
	goName    string       // field name in Go struct
	typ       *match       // match result type
	omitEmpty bool         // set for raw fields and for fields optional in either version
	versions  [2]jsonField // original types and presence, retained for typed output
}

type typePair struct{ left, right ast.Expr }

type comparison struct {
	left, right *model
	cache       map[typePair]*match
	structs     []*match
	names       map[string]bool
}

// compareModels returns all structs that need a declaration. The root is
// always the first of them.
func compareModels(left, right *model, rootName string) ([]*match, error) {
	leftRoot, rightRoot := left.types[rootName], right.types[rootName]
	if leftRoot == nil || rightRoot == nil {
		return nil, fmt.Errorf("root type %q must exist in both models", rootName)
	}
	c := &comparison{left: left, right: right, cache: make(map[typePair]*match), names: make(map[string]bool)}
	root, err := c.compare(leftRoot, rightRoot, rootName)
	if err != nil {
		return nil, err
	}
	if root.shape != "struct" {
		return nil, fmt.Errorf("%s roots must be structs", rootName)
	}
	return c.structs, nil
}

// resolve exposes the type structure behind a type name so callers can compare
// types by their definitions rather than their names
func (m *model) resolve(expr ast.Expr) (ast.Expr, bool) {
	for {
		ident, ok := expr.(*ast.Ident)
		if !ok {
			return expr, false
		}
		if m.custom[ident.Name] {
			return nil, true
		}
		definition := m.types[ident.Name]
		if definition == nil {
			return expr, false
		}
		expr = definition
	}
}

func (c *comparison) compare(left, right ast.Expr, name string) (*match, error) {
	if compatible, err := compatibleDateTime(left, right, [2]*model{c.left, c.right}); err != nil {
		return nil, err
	} else if compatible {
		return &match{shape: "v21.DateTime"}, nil
	}

	if !separateOptionalityDifferences && left != nil && right != nil {
		a, leftPointer := left.(*ast.StarExpr)
		b, rightPointer := right.(*ast.StarExpr)
		if leftPointer != rightPointer {
			if leftPointer {
				return c.compareElem(&match{}, "pointer", a.X, right, name)
			}
			return c.compareElem(&match{}, "pointer", left, b.X, name)
		}
	}

	left, leftRaw := c.left.resolve(left)
	right, rightRaw := c.right.resolve(right)
	pair := typePair{left, right}
	if cached := c.cache[pair]; cached != nil {
		return cached, nil
	}
	node := &match{}
	c.cache[pair] = node
	if leftRaw || rightRaw || left == nil || right == nil {
		node.raw = true
		return node, nil
	}
	switch left := left.(type) {
	case *ast.Ident:
		if right, ok := right.(*ast.Ident); ok && left.Name == right.Name && primitive(left.Name) {
			node.shape = left.Name
			return node, nil
		}
	case *ast.StarExpr:
		if right, ok := right.(*ast.StarExpr); ok {
			return c.compareElem(node, "pointer", left.X, right.X, name)
		}
	case *ast.ArrayType:
		if right, ok := right.(*ast.ArrayType); ok && left.Len == nil && right.Len == nil {
			return c.compareElem(node, "slice", left.Elt, right.Elt, name+"Elem")
		}
	case *ast.StructType:
		if right, ok := right.(*ast.StructType); ok {
			return c.compareStruct(node, left, right, name)
		}
	}
	// Unsupported shapes stay raw
	node.raw = true
	return node, nil
}

func (c *comparison) compareElem(node *match, shape string, left, right ast.Expr, name string) (*match, error) {
	elem, err := c.compare(left, right, name)
	node.shape, node.elem = shape, elem
	if elem != nil {
		node.raw = elem.raw
	}
	return node, err
}

func primitive(name string) bool {
	switch name {
	case "string", "bool", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "float32", "float64":
		return true
	}
	return false
}

func (c *comparison) compareStruct(node *match, left, right *ast.StructType, name string) (*match, error) {
	a, err := structFields(left)
	if err != nil {
		return nil, err
	}
	b, err := structFields(right)
	if err != nil {
		return nil, err
	}
	node.shape = "struct"
	for c.names[name] {
		name += "Type"
	}
	node.name = name
	c.names[name] = true
	c.structs = append(c.structs, node)
	ordered := slices.Sorted(maps.Keys(a))
	for name := range b {
		if _, ok := a[name]; !ok {
			ordered = append(ordered, name)
		}
	}
	slices.Sort(ordered)
	goNames := make(map[string]bool)
	for _, name := range ordered {
		first, second := a[name], b[name]
		goName := first.goName
		if goName == "" {
			goName = second.goName
		}
		for goNames[goName] {
			goName += "Alt"
		}
		goNames[goName] = true
		versions := [2]jsonField{first, second}
		typ := &match{raw: true}
		if !separateOptionalityDifferences || !optionalityDiffers(versions, [2]*model{c.left, c.right}) {
			typ, err = c.compare(first.typ, second.typ, node.name+goName)
			if err != nil {
				return nil, err
			}
		}
		omitEmpty := typ.raw || first.omitEmpty || second.omitEmpty
		node.fields = append(node.fields, fieldMatch{
			jsonName: name, goName: goName, typ: typ, omitEmpty: omitEmpty,
			versions: [2]jsonField{first, second},
		})
	}
	return node, nil
}
