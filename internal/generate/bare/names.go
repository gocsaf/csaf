// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
)

type nameOverride struct {
	Name       string            `json:"name"`
	StructName string            `json:"struct_name"`
	Type       string            `json:"type"`
	TypeName   string            `json:"type_name"` // new name of a named non-struct type
	Constants  map[string]string `json:"constants"` // JSON value -> Go constant name
}

type namesFile struct {
	documents map[string]map[string]nameOverride
	reached   map[string]map[string]bool
}

func readNames(filename string) (*namesFile, error) {
	if filename == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	result := &namesFile{reached: make(map[string]map[string]bool)}
	if err := json.Unmarshal(data, &result.documents); err != nil {
		return nil, err
	}
	for document, entries := range result.documents {
		result.reached[document] = make(map[string]bool)
		for path, entry := range entries {
			if entry.StructName != "" && entry.Type != "" {
				return nil, fmt.Errorf("%s%s: struct_name and type are mutually exclusive", document, path)
			}
			if entry.TypeName != "" && entry.Type != "" {
				return nil, fmt.Errorf("%s%s: type_name and type are mutually exclusive", document, path)
			}
		}
	}
	return result, nil
}

// at returns the override for a document ("advisory", "provider", ...) and a
// JSON path such as "/document/title" and marks the path as reached.
func (n *namesFile) at(document, path string) nameOverride {
	if n == nil {
		return nameOverride{}
	}
	if entry, ok := n.documents[document][path]; ok {
		n.reached[document][path] = true
		return entry
	}
	return nameOverride{}
}

// report writes every path of the names file that was never reached by at
func (n *namesFile) report(layer string, out io.Writer) {
	if n == nil {
		return
	}
	for _, document := range slices.Sorted(maps.Keys(n.documents)) {
		for _, path := range slices.Sorted(maps.Keys(n.documents[document])) {
			if !n.reached[document][path] {
				fmt.Fprintf(out, "%s: unreached names path %s:%q\n", layer, document, path)
			}
		}
	}
}

// applyBareNames walks the bare model from root and sets the Go field names
// given by the "name" entries of the document.
func applyBareNames(root *match, names *namesFile, document string) error {
	if names == nil {
		return nil
	}
	visited := make(map[*match]bool)
	var visit func(*match, *fieldMatch, string) error
	visit = func(node *match, field *fieldMatch, path string) error {
		entry := names.at(document, path)
		if entry.Name != "" && field != nil {
			field.goName = entry.Name
		}
		for !node.raw && (node.shape == "pointer" || node.shape == "slice") {
			if node.shape == "slice" {
				path += "/*"
			}
			node = node.elem
		}
		if node.raw || node.shape != "struct" || visited[node] {
			return nil
		}
		visited[node] = true
		for i := range node.fields {
			child := &node.fields[i]
			if err := visit(child.typ, child, path+"/"+child.jsonName); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(root, nil, "")
}

func namedStruct(node *typedType) (structure, name *typedType, suffix string) {
	for {
		switch node.shape {
		case "pointer":
			node = node.elem
		case "slice":
			node = node.elem
			suffix += "/*"
			name = nil
		case "named":
			if name == nil {
				name = node
			}
			node = node.elem
		case "struct":
			if name == nil && node.name != "" {
				name = node
			}
			return node, name, suffix
		default:
			return nil, nil, suffix
		}
	}
}

// returns all fields of a struct by JSON name
func typedFields(node *typedType) (map[string]*typedField, error) {
	fields := make(map[string]*typedField)
	for i := range node.fields {
		f := &node.fields[i]
		if f.common != nil {
			fields[f.jsonName] = f
		}
	}
	for _, detail := range node.details {
		if detail == nil {
			continue
		}
		for i := range detail.fields {
			f := &detail.fields[i]
			if fields[f.jsonName] != nil {
				return nil, fmt.Errorf("duplicate JSON field %s", f.jsonName)
			}
			fields[f.jsonName] = f
		}
	}
	return fields, nil
}

func converterName(typ string) string {
	for {
		if rest, ok := strings.CutPrefix(typ, "*"); ok {
			typ = rest
		} else if rest, ok := strings.CutPrefix(typ, "[]"); ok {
			typ = rest
		} else {
			break
		}
	}
	return typ + "FromBare"
}

// applyNames walks the shared model along JSON paths and applies the
// overrides of the document: field names, struct names, type replacements,
// type names and constant names. Afterwards unused types are pruned and
// duplicate names are rejected. Does nothing if names is nil.
func (m *typedModel) applyNames(names *namesFile, document string) error {
	if names == nil {
		return nil
	}
	visited := make(map[*typedType]bool)
	requested := make(map[*typedType]string)
	requestedTypes := make(map[*typedType]string)
	requestedConstants := make(map[*typedType]map[string]string)
	var visit func(*typedType, *typedField, string) error
	visit = func(node *typedType, field *typedField, path string) error {
		entry := names.at(document, path)
		// Apply name override to the field.
		if entry.Name != "" && field != nil {
			field.name = entry.Name
		}
		// Apply type override to the field.
		if entry.Type != "" && entry.Type != typedName(node) && field != nil {
			if strings.HasPrefix(m.versionPath, path+"/") {
				return fmt.Errorf("cannot replace type in the version path %s", m.versionPath)
			}
			replacement := &typedType{shape: entry.Type, replacement: true}
			// Replace type where it is used.
			if field.local != nil {
				field.local = replacement
			} else {
				field.common = replacement
			}
			return nil
		}
		if entry.TypeName != "" || len(entry.Constants) > 0 {
			named := node
			for named.shape == "pointer" {
				named = named.elem
			}
			if named.shape != "named" {
				return fmt.Errorf("%s: type_name and constants require a generated named type", path)
			}
			if entry.TypeName != "" {
				if previous := requestedTypes[named]; previous != "" && previous != entry.TypeName {
					return fmt.Errorf("conflicting type names for %s: %s and %s", named.name, previous, entry.TypeName)
				}
				requestedTypes[named] = entry.TypeName
			}
			for value, constantName := range entry.Constants {
				if requestedConstants[named] == nil {
					requestedConstants[named] = make(map[string]string)
				}
				if previous := requestedConstants[named][value]; previous != "" && previous != constantName {
					return fmt.Errorf("conflicting constant names for %q of %s: %s and %s", value, named.name, previous, constantName)
				}
				requestedConstants[named][value] = constantName
			}
		}
		// Apply struct_name override to the named structs.
		structure, typeName, suffix := namedStruct(node)
		if entry.StructName != "" {
			if typeName == nil {
				return fmt.Errorf("%s: struct_name requires a generated named struct", path)
			}
			if previous := requested[typeName]; previous != "" && previous != entry.StructName {
				return fmt.Errorf("conflicting names for %s: %s and %s", typeName.name, previous, entry.StructName)
			}
			requested[typeName] = entry.StructName
		}
		if structure == nil || visited[structure] {
			return nil
		}
		visited[structure] = true
		// Recurse into the struct fields.
		fields, err := typedFields(structure)
		if err != nil {
			return err
		}
		for _, jsonName := range slices.Sorted(maps.Keys(fields)) {
			child := fields[jsonName]
			if err := visit(child.typ(), child, path+suffix+"/"+jsonName); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(m.structures[0], nil, ""); err != nil {
		return err
	}
	for node, name := range requested {
		node.name = name
	}
	for node, name := range requestedTypes {
		node.name = name
	}
	for node, constants := range requestedConstants {
		for value, constantName := range constants {
			found := false
			for i := range node.constants {
				if original, err := strconv.Unquote(node.constants[i].value); err == nil && original == value {
					node.constants[i].name = constantName
					found = true
				}
			}
			if !found {
				return fmt.Errorf("%s has no constant with value %q", node.name, value)
			}
		}
		slices.SortFunc(node.constants, func(a, b localConstant) int { return strings.Compare(a.name, b.name) })
	}
	m.pruneTypes()
	return m.checkDuplicateNames()
}

// checkDuplicateNames reports generated names that are used twice after renaming.
func (m *typedModel) checkDuplicateNames() error {
	seen := make(map[string]bool)
	var names []string
	for _, structure := range m.structures {
		names = append(names, structure.name)
	}
	for _, declaration := range m.localDeclarations {
		names = append(names, declaration.name)
		for _, constant := range declaration.constants {
			names = append(names, constant.name)
		}
	}
	for _, name := range names {
		if seen[name] {
			return fmt.Errorf("name %s is used twice", name)
		}
		seen[name] = true
	}
	return nil
}

// Removes types that should not be part of the output, because unused
func (m *typedModel) pruneTypes() {
	live := make(map[*typedType]bool)
	var visit func(*typedType)
	visit = func(node *typedType) {
		if node == nil || live[node] {
			return
		}
		live[node] = true
		visit(node.elem)
		for _, f := range node.fields {
			if f.common != nil {
				visit(f.common)
			}
		}
		for _, detail := range node.details {
			if detail != nil {
				for _, f := range detail.fields {
					visit(f.local)
				}
			}
		}
	}
	visit(m.structures[0])
	m.structures = slices.DeleteFunc(m.structures, func(t *typedType) bool { return !live[t] })
	m.localDeclarations = slices.DeleteFunc(m.localDeclarations, func(t *typedType) bool { return !live[t] })
}
