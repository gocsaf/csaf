// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package util

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCleanFileName(t *testing.T) {
	for _, x := range [][2]string{
		{`HELLO`, `hello.json`},
		{`hello`, `hello.json`},
		{`cisco-sa-20190513-secureboot.json`, `cisco-sa-20190513-secureboot.json`},
		{``, `.json`},
		{`..`, `_.json`},
		{`../..`, `_.json`},
		{`abc.html`, `abc_html.json`},
		{`abc_.htm__l`, `abc_htm_l.json`},
		{`foo+BAR`, `foo+bar.json`},
	} {
		if got := CleanFileName(x[0]); got != x[1] {
			t.Errorf("%q: Expected %q but got %q.", x[0], x[1], got)
		}
	}
}

func TestConformingFileName(t *testing.T) {
	for _, x := range []struct {
		s string
		b bool
	}{
		{`HELLO`, false},
		{`hello`, false},
		{`cisco-sa-20190513-secureboot.json`, true},
		{`example_company_-_2019-yh3234.json`, true},
		{`rhba-2019_0024.json`, true},
		{`2022__01-a.json`, false},
		{``, false},
		{`..`, false},
		{`../..`, false},
		{`abc.html`, false},
		{`abc_.htm__l`, false},
		{`foo+BAR`, false},
	} {
		if got := ConformingFileName(x.s); got != x.b {
			t.Errorf("%q: Expected %t but got %t.", x.s, x.b, got)
		}
	}
}

func TestIDMatchesFilename(t *testing.T) {
	pathEval := NewPathEval()

	doc := make(map[string]any)
	doc["document"] = map[string]any{
		"tracking": map[string]any{
			"id": "valid.json",
		},
	}

	if err := IDMatchesFilename(pathEval, doc, "valid.json"); err != nil {
		t.Errorf("IDMatchesFilename: Expected nil, got %q", err)
	}

	if err := IDMatchesFilename(pathEval, doc, "different_file_name.json"); err == nil {
		t.Error("IDMatchesFilename: Expected error, got nil")
	}

	doc["document"] = map[string]any{
		"tracking": map[string]any{},
	}
	if err := IDMatchesFilename(pathEval, doc, "valid.json"); err == nil {
		t.Error("IDMatchesFilename: Expected error, got nil")
	}
}

func TestPathExists(t *testing.T) {
	got, err := PathExists("/this/path/does/not/exist")
	if err != nil {
		t.Error(err)
	}
	if got != false {
		t.Error("PathExists: Expected false, got true")
	}
	dir := t.TempDir()
	got, err = PathExists(dir)
	if err != nil {
		t.Error(err)
	}
	if got != true {
		t.Error("PathExists: Expected true, got false")
	}
}

func TestNWriter(t *testing.T) {
	msg := []byte("Gruß!\n")

	first, second := msg[:len(msg)/2], msg[len(msg)/2:]

	var buf bytes.Buffer
	nw := NWriter{Writer: &buf, N: 0}
	_, err1 := nw.Write(first)
	_, err2 := nw.Write(second)

	if err1 != nil || err2 != nil {
		t.Error("Calling NWriter failed")
	}

	if n := int64(len(msg)); nw.N != n {
		t.Errorf("Expected %d bytes, but counted %d.", n, nw.N)
	}

	if out := buf.Bytes(); !bytes.Equal(msg, out) {
		t.Errorf("Expected %q, but got %q", msg, out)
	}
}

func TestWriteToFile(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "test_file")
	wt := bytes.NewBufferString("test_data")
	if err := WriteToFile(filename, wt); err != nil {
		t.Error(err)
	}
	fileData, err := os.ReadFile(filename)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(fileData, []byte("test_data")) {
		t.Errorf("DeepCopy: Expected test_data, got %v", fileData)
	}
}

func TestMakeUniqFile(t *testing.T) {
	dir := t.TempDir()
	_, file, err := MakeUniqFile(dir)
	if err != nil {
		t.Error(err)
	}
	if _, err = file.Write([]byte("test_data")); err != nil {
		t.Error(err)
	}
	if err = file.Close(); err != nil {
		t.Error(err)
	}
}

func Test_mkUniq(t *testing.T) {
	dir := t.TempDir()
	name, err := mkUniq(dir+"/", func(_ string) error {
		return nil
	})
	if err != nil {
		t.Error(err)
	}
	firstTime := true
	name1, err := mkUniq(dir+"/", func(_ string) error {
		if firstTime {
			firstTime = false
			return os.ErrExist
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
	if name == name1 {
		t.Errorf("mkUniq: Expected unique names, got %v and %v", name, name1)
	}
}

func TestDeepCopy(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src/folder0"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "dst"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "dst1"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src/folder0/test_file"), []byte("test_data"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := DeepCopy(filepath.Join(dir, "dst"), filepath.Join(dir, "src")); err != nil {
		t.Error(err)
	}

	fileData, err := os.ReadFile(filepath.Join(dir, "dst/folder0/test_file"))
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(fileData, []byte("test_data")) {
		t.Errorf("DeepCopy: Expected test_data, got %v", fileData)
	}

	if err = DeepCopy("/path/does/not/exist", filepath.Join(dir, "src")); err == nil {
		t.Error("DeepCopy: Expected error, got nil")
	}

	if err = DeepCopy(filepath.Join(dir, "dst1"), "/path/does/not/exist"); err == nil {
		t.Error("DeepCopy: Expected error, got nil")
	}
}
