// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package util

import (
	"hash"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHashFromReader(t *testing.T) {
	r := strings.NewReader("deadbeef")
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	if got, err := HashFromReader(r); !reflect.DeepEqual(want, got) {
		if err != nil {
			t.Error(err)
		}
		t.Errorf("HashFromReader: Expected %v, got %v", want, got)
	}
}

func TestHashFromFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test_file")
	testFile, err := os.Create(filePath)
	if err != nil {
		t.Error(err)
	}

	testFile.WriteString("deadbeef")
	want := []byte{0xde, 0xad, 0xbe, 0xef}

	testFile.Close()

	if got, err := HashFromFile(filePath); !reflect.DeepEqual(want, got) {
		if err != nil {
			t.Error(err)
		}
		t.Errorf("HashFromFile: Expected %v, got %v", want, got)
	}
}

type deadbeefHash struct {
	hash.Hash
}

func (deadbeefHash) Write(p []byte) (int, error) { return len(p), nil }
func (deadbeefHash) Sum(_ []byte) []byte         { return []byte{0xde, 0xad, 0xbe, 0xef} }

func TestWriteHashToFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test_file")

	hashArg := deadbeefHash{}
	nameArg := "name"
	want := "deadbeef " + nameArg + "\n"

	if err := WriteHashToFile(filePath, nameArg, hashArg, []byte{}); err != nil {
		t.Error(err)
	}
	testFile, err := os.Open(filePath)
	if err != nil {
		t.Error(err)
	}
	defer testFile.Close()
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Error(err)
	}
	if got := string(fileContent); got != want {
		t.Errorf("WriteHashToFile: Expected %v, got %v", want, got)
	}
}

func TestWriteHashSumToFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test_file")

	sum := []byte{0xde, 0xad, 0xbe, 0xef}
	nameArg := "name"
	want := "deadbeef " + nameArg + "\n"

	if err := WriteHashSumToFile(filePath, nameArg, sum); err != nil {
		t.Error(err)
	}
	testFile, err := os.Open(filePath)
	if err != nil {
		t.Error(err)
	}
	defer testFile.Close()
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Error(err)
	}
	if got := string(fileContent); got != want {
		t.Errorf("WriteHashSumToFile: Expected %v, got %v", want, got)
	}
}
