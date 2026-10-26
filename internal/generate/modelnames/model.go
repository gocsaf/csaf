// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"maps"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

const modulePath = "github.com/gocsaf/csaf/v3"

type sourcePackage struct {
	types  map[string]declaration
	custom map[string]bool
}

type sourceFile struct {
	pkg     *sourcePackage
	imports map[string]string
}

type declaration struct {
	spec *ast.TypeSpec
	file *sourceFile
}

type resolvedStruct struct {
	node           *ast.StructType
	file           *sourceFile
	goName         string
	jsonPathSuffix string
}

type jsonField struct {
	goName string
	typ    ast.Expr
	file   *sourceFile
}

// A single exporter owns the package cache and the current root's traversal.
type exporter struct {
	repo     string
	packages map[string]*sourcePackage
	entries  map[string]entry
	visited  map[*ast.StructType]bool
}

func (e *exporter) exportRoot(root modelRoot) (map[string]entry, error) {
	pkg, err := e.loadPackage(root.dir)
	if err != nil {
		return nil, err
	}
	decl, ok := pkg.types[root.name]
	if !ok {
		return nil, fmt.Errorf("root %s not found in %s", root.name, root.dir)
	}

	// Roots share loaded packages, but each has its own output and first visits.
	e.entries = make(map[string]entry)
	e.visited = make(map[*ast.StructType]bool)
	if err := e.visitType("", "", decl.spec.Name, decl.file); err != nil {
		return nil, err
	}
	return e.entries, nil
}

func (e *exporter) visitType(jsonPath, goName string, typ ast.Expr, file *sourceFile) error {
	structure, err := e.resolveStruct(typ, file)
	if err != nil {
		return fmt.Errorf("%s: %w", jsonPath, err)
	}

	value := entry{Name: goName}
	// If not struct or anonymous struct.
	if structure == nil || structure.goName == "" {
		value.Type, err = typeString(typ)
		if err != nil {
			return err
		}
	} else {
		value.StructName = structure.goName
	}
	e.entries[jsonPath] = value

	if structure == nil || e.visited[structure.node] {
		return nil
	}
	e.visited[structure.node] = true
	fields, err := e.collectJSONFields(structure)
	if err != nil {
		return fmt.Errorf("%s: %w", jsonPath, err)
	}
	for _, jsonName := range slices.Sorted(maps.Keys(fields)) {
		field := fields[jsonName]
		childPath := jsonPath + structure.jsonPathSuffix + "/" + jsonName
		if err := e.visitType(childPath, field.goName, field.typ, field.file); err != nil {
			return err
		}
	}
	return nil
}

// Resolve if type is struct. Return definition if it is, to traverse its fields.
func (e *exporter) resolveStruct(typ ast.Expr, file *sourceFile) (*resolvedStruct, error) {
	var goName, jsonPathSuffix string
	for {
		var decl declaration
		switch node := typ.(type) {
		case *ast.StarExpr:
			typ = node.X
			continue
		case *ast.ArrayType:
			typ = node.Elt
			jsonPathSuffix += "/*"
			goName = ""
			continue
		case *ast.StructType:
			return &resolvedStruct{
				node: node, file: file,
				goName: goName, jsonPathSuffix: jsonPathSuffix,
			}, nil
		case *ast.Ident:
			var ok bool
			decl, ok = file.pkg.types[node.Name]
			if !ok {
				return nil, nil
			}
		case *ast.SelectorExpr:
			qualifier, ok := node.X.(*ast.Ident)
			if !ok {
				return nil, nil
			}
			importPath := file.imports[qualifier.Name]
			dir, local := strings.CutPrefix(importPath, modulePath+"/")
			if !local {
				return nil, nil
			}
			pkg, err := e.loadPackage(dir)
			if err != nil {
				return nil, err
			}
			decl, ok = pkg.types[node.Sel.Name]
			if !ok {
				return nil, fmt.Errorf("type %s not found in %s", node.Sel.Name, importPath)
			}
		default:
			return nil, nil
		}

		// Treat custom types as leaves.
		if decl.file.pkg.custom[decl.spec.Name.Name] {
			return nil, nil
		}
		if goName == "" {
			var err error
			goName, err = typeString(typ)
			if err != nil {
				return nil, err
			}
		}
		typ, file = decl.spec.Type, decl.file
	}
}

// version details and contribute their fields to the same JSON object.
func (e *exporter) collectJSONFields(structure *resolvedStruct) (map[string]jsonField, error) {
	fields := make(map[string]jsonField)
	for _, field := range structure.node.Fields.List {
		// Embedded struct fields have no name and no tag.
		// Traverse them recursively to collect their JSON fields into the parent struct.
		if len(field.Names) == 0 && field.Tag == nil {
			child, err := e.resolveStruct(field.Type, structure.file)
			if err != nil {
				return nil, err
			}
			if child == nil {
				return nil, fmt.Errorf("unsupported embedded type in %s", structure.goName)
			}
			childFields, err := e.collectJSONFields(child)
			if err != nil {
				return nil, err
			}
			for name, childField := range childFields {
				// Prevent embedded fields from silently overwriting an existing JSON property.
				if _, exists := fields[name]; exists {
					return nil, fmt.Errorf("duplicate JSON property %q in %s", name, structure.goName)
				}
				fields[name] = childField
			}
			continue
		}

		if len(field.Names) != 1 || field.Tag == nil {
			return nil, fmt.Errorf("expected a named field with a JSON tag in %s", structure.goName)
		}
		tag, err := strconv.Unquote(field.Tag.Value)
		if err != nil {
			return nil, err
		}
		jsonName, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
		if jsonName == "" {
			return nil, fmt.Errorf("missing JSON name for %s.%s", structure.goName, field.Names[0].Name)
		}
		// Prevent directly declared fields from silently overwriting an existing JSON property.
		if _, exists := fields[jsonName]; exists {
			return nil, fmt.Errorf("duplicate JSON property %q in %s", jsonName, structure.goName)
		}
		fields[jsonName] = jsonField{goName: field.Names[0].Name, typ: field.Type, file: structure.file}
	}
	return fields, nil
}

func (e *exporter) loadPackage(dir string) (*sourcePackage, error) {
	if pkg := e.packages[dir]; pkg != nil {
		return pkg, nil
	}
	paths, err := filepath.Glob(filepath.Join(e.repo, dir, "*.go"))
	if err != nil {
		return nil, err
	}
	pkg := &sourcePackage{types: make(map[string]declaration), custom: make(map[string]bool)}
	for _, filename := range paths {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		node, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			return nil, err
		}
		file := &sourceFile{pkg: pkg, imports: make(map[string]string)}
		// Resolve qualifiers such as v21 using this file's imports and aliases.
		for _, spec := range node.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return nil, err
			}
			name := path.Base(importPath)
			if spec.Name != nil {
				name = spec.Name.Name
			}
			file.imports[name] = importPath
		}
		for _, decl := range node.Decls {
			switch decl := decl.(type) {
			case *ast.GenDecl:
				if decl.Tok != token.TYPE {
					continue
				}
				// Keep the source file so referenced types use the correct import context.
				for _, spec := range decl.Specs {
					typ := spec.(*ast.TypeSpec)
					pkg.types[typ.Name.Name] = declaration{spec: typ, file: file}
				}
			case *ast.FuncDecl:
				if decl.Recv == nil {
					continue
				}
				switch decl.Name.Name {
				case "MarshalJSON", "UnmarshalJSON":
					receiver := decl.Recv.List[0].Type
					if pointer, ok := receiver.(*ast.StarExpr); ok {
						receiver = pointer.X
					}
					if name, ok := receiver.(*ast.Ident); ok {
						pkg.custom[name.Name] = true
					}
				}
			}
		}
	}
	e.packages[dir] = pkg
	return pkg, nil
}

func typeString(typ ast.Expr) (string, error) {
	var out bytes.Buffer
	err := format.Node(&out, token.NewFileSet(), typ)
	return out.String(), err
}
