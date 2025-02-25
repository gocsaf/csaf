# Development

## Supported Go versions

We support the latest version and the one before
the latest version of Go (currently 1.23 and 1.24).

## Generated files

Some source code files are machine generated. At the moment these are only
[cvss20enums.go](../csaf/cvss20enums.go) and [cvss3enums.go](../csaf/cvss3enums.go) on the
basis of the [Advisory JSON schema](../csaf/schema/csaf_json_schema.json).

If you change the source files please regenerate the generated files
with `go generate ./...` in the root folder and add the updated files
to the version control.

If you plan to add further machine generated files ensure that they
are marked with comments like
```
// THIS FILE IS MACHINE GENERATED. EDIT WITH CARE!
```
.
