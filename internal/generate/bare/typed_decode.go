// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import "strings"

// hasReplacement returns true if the type tree at root contains a type that should be replaced
func hasReplacement(root *typedType) bool {
	visited := make(map[*typedType]bool)
	var visit func(*typedType) bool
	visit = func(node *typedType) bool {
		if node == nil || visited[node] {
			return false
		}
		visited[node] = true
		if node.replacement || visit(node.elem) {
			return true
		}
		for _, f := range node.fields {
			if visit(f.common) {
				return true
			}
		}
		return false
	}
	return visit(root)
}

func (c *converterEmitter) customValue(call, source, target string, path errorPath) {
	c.write("converted,err := %s(%s)\nif err != nil { return target, %s }\n%s = converted\n", call, source, path.wrap(": "), target)
}

func (c *converterEmitter) rawValue(source, target string, to *typedType, path errorPath) {
	if to.replacement {
		call := converterName(typedName(to))
		c.customValue(call, source, target, path)
	} else if hasReplacement(to) {
		call := c.rawDecoder(to)
		c.customValue(call, source, target, path)
	} else {
		c.write("if err := json.Unmarshal(%s, &%s); err != nil { return target, %s }\n", source, target, path.wrap(": "))
	}
}

// rawDecoder generates a decoder function for a type that contains a
// replacement type somewhere inside, so plain json.Unmarshal cannot be used.
// The generated function takes json.RawMessage and returns the decoded value
// of node's type. It splits the JSON (pointer, slice, map, struct
// fields) and calls the replacement's FromBare converter where needed.
// Returns the name of the generated function, derived from its target type.
func (c *converterEmitter) rawDecoder(node *typedType) string {
	typ := typedName(node)
	if known := c.decoderNames[typ]; known != "" {
		return known
	}
	name := "decodeBare" + strings.NewReplacer("[]", "Slice", "*", "Pointer", "map[string]", "Map", ".", "").Replace(typ)
	c.decoderNames[typ] = name
	d := &converterEmitter{decoderNames: c.decoderNames}
	d.write("func %s(data json.RawMessage) (%s,error) {\nvar target %s\n", name, typ, typ)
	body := node
	for body.shape == "named" {
		body = body.elem
	}
	switch body.shape {
	case "pointer":
		child := c.rawDecoder(body.elem)
		d.write("if bytes.Equal(bytes.TrimSpace(data), []byte(\"null\")) { return target,nil }\nvalue,err := %s(data)\nif err != nil {return target,err}\ntarget = &value\n", child)
	case "slice", "map":
		container := "[]"
		if body.shape == "map" {
			container = "map[string]"
		}
		d.write("var values %sjson.RawMessage\nif err := json.Unmarshal(data,&values);err != nil {return target,err}\n", container)
		if body.shape == "slice" {
			d.write("if values != nil {target = make(%s,len(values))}\n", typ)
		} else {
			d.write("if values != nil {target = make(%s)}\n", typ)
		}
		d.write("for i,raw := range values {\nvar value %s\n", typedName(body.elem))
		path := fieldErrorPath("")
		if body.shape == "slice" {
			path = path.indexed("i")
		}
		d.rawValue("raw", "value", body.elem, path)
		d.write("target[i] = value\n}\n")
	case "struct":
		d.write("var fields map[string]json.RawMessage\nif err := json.Unmarshal(data,&fields);err != nil {return target,err}\n")
		for _, f := range body.fields {
			d.write("if raw,present := fields[%q];present {\n", f.jsonName)
			d.rawValue("raw", "target."+f.name, f.common, fieldErrorPath(f.jsonName))
			d.write("}\n")
		}
	default:
		d.write("if err := json.Unmarshal(data,&target);err != nil {return target,err}\n")
	}
	d.write("return target,nil\n}\n\n")
	c.decoders = append(c.decoders, d.decoders...)
	c.decoders = append(c.decoders, d.out.String())
	return name
}
