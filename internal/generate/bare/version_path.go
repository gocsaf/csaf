// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"strings"
)

func bareVersionAccess(root *match, path string) (string, error) {
	var access []string
	for _, name := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		for root.shape == "pointer" {
			root = root.elem
		}
		var field *fieldMatch
		for i := range root.fields {
			if root.fields[i].jsonName == name {
				field = &root.fields[i]
				break
			}
		}
		if field == nil {
			return "", fmt.Errorf("version path %s not found in bare", path)
		}
		access = append(access, field.goName)
		root = field.typ
	}
	return strings.Join(access, "."), nil
}

func sharedVersionAccess(root *typedType, path string) (string, error) {
	var access []string
	for _, name := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		for root.shape == "pointer" {
			root = root.elem
		}
		var field *typedField
		for i := range root.fields {
			if root.fields[i].jsonName == name {
				field = &root.fields[i]
				break
			}
		}
		if field == nil || field.common == nil {
			return "", fmt.Errorf("version path %s not found in shared", path)
		}
		access = append(access, field.name)
		root = field.common
	}
	return strings.Join(access, "."), nil
}
