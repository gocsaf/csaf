package bare

import (
	"io"
	"strconv"
)

/*
type versioned[A, B any] struct {
	raw json.RawMessage
	v20 *A
	v21 *B
}

type missing any
*/

type preCSF struct {
	//Schema versioned[int, string]
	Version *string `json:"csaf_version"`
}

type Vulnerabilities interface {
	Foo() string
}

type vul1 struct {
	x int
}

type vul2 string

func (v1 *vul1) Foo() string {
	return strconv.Itoa(v1.x)
}

func (v2 vul2) Foo() string {
	return string(v2)
}

type Document struct {
	version         *string
	Vulnerabilities // vulnerabilities
}

func parsePre(io.Reader) (*preCSF, error) {
	// TDDO: Implement me!
	return nil, nil
}

func LoadDoc(r io.Reader) (*Document, error) {
	pd, err := parsePre(r)
	if err != nil {
		return nil, err
	}
	var d Document

	if pd.Version == nil || *pd.Version == "1.0" {
		d.Vulnerabilities = &vul1{x: 42}
	} else {
		d.Vulnerabilities = vul2("Hello")
	}

	return &d, nil
}

func (d *Document) Version() string {
	if d.version == nil {
		return "Version 1.0"
	}
	return *d.version
}

/*
   var d Document
   d.Foo

*/
