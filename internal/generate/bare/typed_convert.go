// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"fmt"
	"strconv"
)

// consumeBare controls whether generated converters clear their sources.
// Changing this setting requires regenerating the converters.
const consumeBare = true

type converterEmitter struct {
	out    bytes.Buffer
	serial int
}

func (c *converterEmitter) write(format string, args ...any) {
	fmt.Fprintf(&c.out, format, args...)
}

func (c *converterEmitter) temporary() string {
	c.serial++
	return fmt.Sprintf("value%d", c.serial)
}

func (c *converterEmitter) sourceType(t *match) string {
	if t.raw {
		return "json.RawMessage"
	}
	switch t.shape {
	case "struct":
		return "bare." + t.name
	case "pointer":
		return "*" + c.sourceType(t.elem)
	case "slice":
		return "[]" + c.sourceType(t.elem)
	default:
		return t.shape
	}
}

func (c *converterEmitter) clear(source string, t *match) {
	if !consumeBare {
		return
	}
	switch {
	case t.raw || t.shape == "pointer" || t.shape == "slice":
		c.write("%s = nil\n", source)
	case t.shape == "string" || t.shape == "v21.DateTime":
		c.write("%s = \"\"\n", source)
	case t.shape == "bool":
		c.write("%s = false\n", source)
	case t.shape == "struct":
		c.write("%s = %s{}\n", source, c.sourceType(t))
	default:
		c.write("%s = 0\n", source)
	}
}

// value emits conversion of one value. Struct recursion emits a helper call.
// It does not recursively emit another function definition.
func (c *converterEmitter) value(source, target string, from *match, to *typedType, path string) error {
	// Unmarshal raw JSON into structured types.
	if from.raw {
		c.write("if len(%s) > 0 {\n", source)
		c.write("if err := json.Unmarshal(%s, &%s); err != nil { return target, fmt.Errorf(\"%%s: %%w\", %s, err) }\n", source, target, path)
		c.write("}\n")
		c.clear(source, from)
		return nil
	}
	// Direct assignment of same-typed values, that are not structs.
	if !containsStruct(to) && c.sourceType(from) == typedName(to) {
		c.write("%s = %s\n", target, source)
		c.clear(source, from)
		return nil
	}
	switch to.shape {
	case "struct":
		// Convert structs with their respective helper functions.
		c.write("{\nconverted, err := fromBare%s(&(%s), v)\nif err != nil { return target, fmt.Errorf(\"%%s.%%w\", %s, err) }\n%s = converted\n}\n", to.name, source, path, target)
	case "pointer":
		if from.shape != "pointer" {
			return fmt.Errorf("pointer shape mismatch at %s", path)
		}
		c.write("if %s != nil {\n%s = new(%s)\n", source, target, typedName(to.elem))
		// Dereference the pointer for the recursive call.
		if err := c.value("*("+source+")", "*("+target+")", from.elem, to.elem, path); err != nil {
			return err
		}
		c.write("}\n")
	case "slice":
		if from.shape != "slice" {
			return fmt.Errorf("slice shape mismatch at %s", path)
		}
		index := c.temporary()
		c.write("if %s != nil {\n%s = make(%s, len(%s))\nfor %s := range %s {\n", source, target, typedName(to), source, index, source)
		// Element path only used for error messages.
		elementPath := fmt.Sprintf("fmt.Sprintf(\"%%s[%%d]\", %s, %s)", path, index)
		if err := c.value("("+source+")["+index+"]", "("+target+")["+index+"]", from.elem, to.elem, elementPath); err != nil {
			return err
		}
		c.write("}\n}\n")
	default:
		return fmt.Errorf("unsupported conversion from %s to %s at %s", c.sourceType(from), typedName(to), path)
	}
	c.clear(source, from)
	return nil
}

func (m *typedModel) emitConverter(packageName string) ([]byte, error) {
	c := &converterEmitter{}
	for _, node := range m.structures {
		if node.bare == nil || node.bare.raw {
			return nil, fmt.Errorf("shared struct %s has no structured bare counterpart", node.name)
		}
	}
	c.write("type version uint8\nconst (versionUnknown version = iota; version20; version21)\n\n")
	root := m.structures[0]
	versionField := map[string]string{"CSAF": "Document.CSAFVersion", "Provider": "MetadataVersion", "Aggregator": "AggregatorVersion"}[root.name]
	if versionField == "" {
		return nil, fmt.Errorf("no version field configured for %s", root.name)
	}
	c.write("// FromBare converts source to a structured representation.\n")
	if consumeBare {
		c.write("// Source must be exclusively owned. It is consumed and emptied on success.\n// On error it may be partially consumed and must not be reused.\n")
	} else {
		c.write("// Source remains unchanged, including on error. Common pointer and primitive\n// slice data may be shared with the result.\n")
	}
	c.write("func FromBare(source *bare.%s) (*%s, error) {\nif source == nil { return nil, fmt.Errorf(\"nil source\") }\nvar v version\nswitch source.%s {\ncase \"2.0\": v = version20\ncase \"2.1\": v = version21\ndefault: return nil, fmt.Errorf(\"unsupported version %%q\", source.%s)\n}\nresult, err := fromBare%s(source, v)\nif err != nil { return nil, err }; return &result, nil\n}\n", root.name, root.name, versionField, versionField, root.name)

	// Emit the recursive conversion functions for each struct.
	for _, node := range m.structures {
		input := node.bare
		c.write("func fromBare%s(source *%s, v version) (%s, error) {\nvar target %s\n", node.name, c.sourceType(input), node.name, node.name)
		fields := make(map[string]fieldMatch)
		for _, f := range input.fields {
			fields[f.jsonName] = f
		}
		for _, f := range node.fields {
			// Skip non common fields here
			if f.common == nil {
				continue
			}
			original, ok := fields[f.jsonName]
			if !ok {
				return nil, fmt.Errorf("missing bare field %s.%s", node.name, f.jsonName)
			}
			if err := c.value("source."+original.goName, "target."+f.name, original.typ, f.common, strconv.Quote(f.jsonName)); err != nil {
				return nil, err
			}
		}
		hasDetails := len(details(node, 0)) > 0 || len(details(node, 1)) > 0
		if hasDetails {
			c.write("switch v {\n")
			for i := range 2 {
				c.write("case version%d:\n", 20+i)
				fs := details(node, i)
				if len(fs) == 0 {
					c.write("// No version details for version %d\n", 20+i)
					continue
				}
				c.write("details := &%s%dDetails{}\n", node.name, 20+i)
				for _, f := range fs {
					original := fields[f.jsonName]
					if original.typ == nil || !original.typ.raw {
						return nil, fmt.Errorf("version detail %s.%s requires a raw bare field", node.name, f.jsonName)
					}
					source := "source." + original.goName
					c.write("if len(%s) > 0 {\nif err := json.Unmarshal(%s, &details.%s); err != nil { return target, fmt.Errorf(%q, err) }\n}\n", source, source, f.name, f.jsonName+": %w")
					c.clear(source, original.typ)
				}
				c.write("target.%s%dDetails = details\n", node.name, 20+i)
			}
			c.write("}\n")
		}
		if consumeBare {
			c.write("*source = %s{}\n", c.sourceType(input))
		}
		c.write("return target, nil\n}\n")
	}
	return typedSource(packageName, c.out.String())
}
