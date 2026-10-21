// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

type model struct {
	types  map[string]ast.Expr
	custom map[string]bool
}

func loadModel(dir string) (*model, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	result := &model{types: make(map[string]ast.Expr), custom: make(map[string]bool)}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fst := token.NewFileSet()
		file, err := parser.ParseFile(fst, path, nil, 0)
		if err != nil {
			return nil, err
		}
		for _, declaration := range file.Decls {
			switch node := declaration.(type) {
			case *ast.GenDecl:
				if node.Tok != token.TYPE {
					continue
				}
				for _, specification := range node.Specs {
					spec := specification.(*ast.TypeSpec)
					result.types[spec.Name.Name] = spec.Type
				}
			case *ast.FuncDecl:
				if node.Recv != nil && node.Name.Name == "UnmarshalJSON" {
					receiver := node.Recv.List[0].Type
					if pointer, ok := receiver.(*ast.StarExpr); ok {
						receiver = pointer.X
					}
					if name, ok := receiver.(*ast.Ident); ok {
						result.custom[name.Name] = true
					}
				}
			}
		}
	}
	return result, nil
}

type jsonField struct {
	name      string
	goName    string
	typ       ast.Expr
	omitEmpty bool
}

// required follows the versioned model generator's JSON tag convention.
func (f jsonField) required() bool {
	return f.typ != nil && !f.omitEmpty
}

func structFields(structure *ast.StructType) (map[string]jsonField, error) {
	fields := make(map[string]jsonField)
	for _, field := range structure.Fields.List {
		if len(field.Names) != 1 || field.Tag == nil {
			return nil, fmt.Errorf("expected named field with JSON tag")
		}
		tag, err := strconv.Unquote(field.Tag.Value)
		if err != nil {
			return nil, err
		}
		name, options, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			return nil, fmt.Errorf("missing JSON property name for %s", field.Names[0].Name)
		}
		if _, exists := fields[name]; exists {
			return nil, fmt.Errorf("duplicate JSON property %q", name)
		}
		omitEmpty := strings.Contains(","+options+",", ",omitempty,")
		fields[name] = jsonField{name, field.Names[0].Name, field.Type, omitEmpty}
	}
	return fields, nil
}
