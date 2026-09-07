<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
-->

# CSAF 2.1 model port

## Generator selection

We use `github.com/atombender/go-jsonschema@v0.24.1` with `--only-models`.
Schema validation is still handled by `santhosh-tekuri/jsonschema`.
None of the generators examined produced a sufficient model with correct
validation for all schemas without additional work.

| Variant                                    | Concrete result                                                                                                                                                                                                                 |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| go-jsonschema `v0.24.1`, models only       | Produces compiling, largely typed code. The tested `oneOf` fields for CVSS 3, the CVSS 4 score and severity, and the SSVC schema version are projected incorrectly. `time.Time` would normalize timestamps during a round trip. |
| go-jsonschema with generated validation    | The generator exits with status 0, but writes Go code that cannot be formatted because 112 regular expressions are not escaped. A syntax-only fix would not add the missing full JSON Schema semantics.                         |
| quicktype `26.0.0`                         | Stops before producing Go output at the valid CVSS 4 schema: `Can't have non-specified required properties but forbidden additionalTypes`.                                                                                      |
| Modelina CLI `5.10.1`                      | Reduces the root schema to `AnyModel`, cannot generate this model for Go, nevertheless exits with status 0, and leaves the output directory empty.                                                                              |
| schemagen `0.0.8`                          | Writes Go code that uses, among other things, `type $schema`, URL components, and `AMBER+STRICT` as identifiers. Even with all schemas local, references remain unresolved and the code does not compile.                       |
| esdigo `0.4.1`                             | Stops at the advisory schema without output because of the reference to `extension-content.json`. A run with all local references also produces no output within 30 seconds and is terminated.                                  |
| ChristopherDavenport/jsonschema `v0.0.5`   | Projects many types and validations, but cannot format or write the advisory output because of identifiers derived from `$schema`, URLs, URNs, and `AMBER+STRICT`. The separately tested ROLIE model also does not compile.     |
| emersion/go-jsonschema, revision `a828df1` | Produces compiling code, but loses the required model structure: mostly one large `Root` with anonymous nested structures. CVSS 2/3/4, SSVC, and extensions remain `json.RawMessage`.                                           |

## Generation and Python scripts

The `generate_v21` target in the [Makefile](../Makefile) runs the pipeline:

```sh
make generate_v21
```

The OASIS inputs are pinned to commit
[`fd04963f836406b2691c861feb80db58577fc9c7`][O21]. CVSS and SSVC
resources are downloaded from their servers during generation and then embedded.
Runtime validation is therefore independent of the network. A later regeneration
may nevertheless use changed external schemas.

### `prepare_schema.py`

[Source code](../internal/generate/prepare_schema.py)

- Loads the schemas from the commit: advisory, provider, aggregator,
  extension content, extension metadata, extension metaschema, and meta.
- Rewrites references to the local files loaded earlier.
- Copies referenced publisher, TLP, role, and URL definitions into `$defs` and
  rewrites the corresponding references. Otherwise, the generator cannot process
  the valid direct references to `properties`.

### `prepare_model.py`

[Source code](../internal/generate/prepare_model.py)

The script repairs known issues in the generator output:

| Generator output                                   | Replacement                               |
| -------------------------------------------------- | ----------------------------------------- |
| CVSS 3 field as `interface{}`                      | Interface `CVSSV3` with concrete variants |
| CVSS 4 fields with types from the NONE branch      | `float64` and `CVSSV40Severity`           |
| CVSS 4 severity constant types as `interface{}`    | Named string types                        |
| Extension metaschema `Required` as `[]interface{}` | `[]string`                                |
| SSVC `SchemaVersion` as `string`                   | `SSVCV2SchemaVersion`                     |
| `time.Time`                                        | String-based `DateTime`                   |

The script also names branch elements, preserves the Go fields `PGPKeys` and
`Aggregator.Version`, and shares equivalent publisher and role types.

The severity constants and the exact `Required` list are still enforced by schema
validation. Go string types alone cannot enforce their allowed values.

The remaining empty interfaces are retained for these reasons:

- `ExtensionContentJsonContent` is a `map[string]interface{}` because
  [extension-content.json](../csaf/v21/schema/extension-content.json),
  `/properties/content`, explicitly allows arbitrary properties and values via
  `additionalProperties: true`. The content must be a nonempty object, but its
  fields depend on the specific extension schema and cannot be predefined by
  the library.
- `Schema` remains `interface{}` in `ExtensionMetaschemaJson.Defs` and
  `ExtensionMetaschemaJsonProperties.Content`. In
  [extension-metaschema.json](../csaf/v21/schema/extension-metaschema.json),
  `/$defs/schema` combines the JSON Schema metaschemas using `allOf` and a
  dynamic anchor. Modeling these recursive schema descriptions would require
  substantially more than a simple type replacement.

### `bundle_schema.py`

[Source code](../internal/generate/bundle_schema.py)

The script first registers the prepared root schemas and then recursively follows
`$ref` and `$schema`. The fetch URI and declared `$id` or `id` are taken into
account. Known resources prevent repeated loading and reference cycles.

The output consists of individual JSON files under `csaf/v21/schema` and
`schemas_generated.go`. OASIS schemas are placed directly in the schema
directory, and external resources under `external/<host>/<path>`. The generated
Go file embeds all required files with `go:embed` and maps schema URIs to their
files. The fetch URI and declared ID point to the same file.

## Validation and loading

The functions `ValidateCSAF`, `ValidateProviderMetadata`,
`ValidateAggregator`, and `ValidateROLIE` keep their signatures but delegate
their logic to [csaf/v21/validation.go](../csaf/v21/validation.go).

`Advisory.Validate()`, `ProviderMetadata.Validate()`, and `Aggregator.Validate()`
check the current object against the bundled 2.1 schemas.

`json.Marshal` and `WriteTo` do not validate automatically. Direct decoding of
provider or aggregator models does not perform a full schema check. Use the
validation methods explicitly. `LoadProviderMetadata` validates before decoding,
and advisory decoding performs schema validation.

## Changes to the models and callers

### TLP and feed checking

The access rules are defined in the standards:

- [S20, 7.1.4](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#714-requirement-4-tlpwhite):
  > If the CSAF document is labeled TLP:WHITE, it MUST be freely accessible.
- [S21, 7.1.4](https://docs.oasis-open.org/csaf/csaf/v2.1/csd02/csaf-v2.1-csd02.html#requirement-4-tlp-clear):
  > If the CSAF document is labeled TLP:CLEAR, it MUST be freely accessible.
- [S20, 7.1.5](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#715-requirement-5-tlpamber-and-tlpred):
  > CSAF documents labeled TLP:AMBER or TLP:RED MUST be access protected.
- [S21, 7.1.5](https://docs.oasis-open.org/csaf/csaf/v2.1/csd02/csaf-v2.1-csd02.html#requirement-5-tlp-amber-tlp-amber-strict-and-tlp-red):
  > CSAF documents labeled TLP:AMBER, TLP:AMBER+STRICT or TLP:RED MUST be access protected.

The checker therefore replaces `TLPLabelWhite` with `TLPLabelClear` and includes
AMBER+STRICT in the access protection check.

The new schema also requires `distribution`, with `tlp` inside it and `label`
inside that, through the respective `required` lists. Missing labels are
therefore no longer treated as `TLPLabelUnlabeled`, but as invalid values. The
allowed labels are listed in section 3.2.2.5.3 of S21.

The two relevant places in the advisory schemas are:

- In the [CSAF 2.0 schema](../csaf/schema/csaf_json_schema.json),
  `/properties/document/required` does not contain `distribution`. `label` is
  required only under
  `/properties/document/properties/distribution/properties/tlp/required`.
- In the [CSAF 2.1 schema](../csaf/v21/schema/csaf.json),
  `/properties/document/required` contains `distribution`,
  `/properties/document/properties/distribution/required` contains `tlp`, and
  `/properties/document/properties/distribution/properties/tlp/required`
  contains `label`.

### Provider

In the [2.1 provider schema][P21],
`/properties/distributions/items/properties/directory` describes the new
Directory object:

In the [2.0 provider schema][P20], only `directory_url` was available. Therefore,
`$.distributions[*].directory_url` becomes
`$.distributions[*].directory.url`. We also added `directory.tlp_label`.

For feeds, the new schema has the following under
`/properties/distributions/items/properties/rolie/properties/feeds/items`:

```json
"required": ["last_updated", "tlp_label", "url"]
```

The old schema had only `tlp_label` and `url`.

Example:

CSAF 2.0:

```json
{
  "distributions": [
    {
      "directory_url": "https://example.org/csaf/"
    },
    {
      "rolie": {
        "feeds": [
          {
            "tlp_label": "GREEN",
            "url": "https://example.org/green/feed.json"
          }
        ]
      }
    }
  ]
}
```

CSAF 2.1:

```json
{
  "distributions": [
    {
      "directory": {
        "tlp_label": "GREEN",
        "url": "https://example.org/csaf/"
      }
    },
    {
      "rolie": {
        "feeds": [
          {
            "last_updated": "2026-09-05T12:00:00Z",
            "tlp_label": "GREEN",
            "url": "https://example.org/green/feed.json"
          }
        ]
      }
    }
  ]
}
```

`AddDirectoryDistribution(url, label)` creates the new Directory object and must
therefore now also accept the label.

### Publisher and OpenPGP keys

S20/S21 section 7.1.7 and the provider schemas.
In the new schema, a key requires both a fingerprint and a URL. In the old schema,
only the URL was required.

Publisher contact details move from `contact_details` to the `contact`
object, which can contain `details`, `email`, and `public_openpgp_key_url`.
`ProviderMetadata.Publisher` is now a value rather than a pointer.
`AdvisorySummary.Publisher` remains a pointer. `PGPKey.URL` is a `URLT` value
rather than a pointer, and `Fingerprint` is a string alias.

### Metadata construction and Go field shapes

S20/S21 sections 7.1.7 and 7.1.21 and the provider and aggregator schemas.

- Metadata versions must be 2.1. Use `MetadataVersion21` and `AggregatorVersion21`.
- Metadata timestamps use string-based `DateTime` values instead of `TimeStamp`
  pointers. Use `NewDateTime(t)` to construct them and `.Time()` to parse them.
  ROLIE feed timestamps still use `TimeStamp`.
- Required fields commonly use values where the 2.0 model used pointers.
  Updating type names alone is therefore insufficient.
  Optional fields and collections follow their current model declarations.

### Product tree and PURL examples

S20 section 3.2.2.4 describes `relationships`. S21 section 3.2.3.4 replaces
them with `product_paths`. The `full_product_name` contained in it is relevant
for searching product names.

| Old                                                                 | New                                                                              |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `ProductTree.FullProductNames` points to a list of product pointers | Slice of product values                                                          |
| `Branches` contains branch pointers                                 | Slice of named `Branch` values. Nested `Branch.Branches` is a pointer to a slice |
| `RelationShips[].FullProductName`                                   | `ProductPaths[].FullProductName`                                                 |
| `FullProductName.ProductID` is a pointer                            | `ProductID` value                                                                |
| `helper.PURL`                                                       | `helper.Purls []string`                                                          |

The PURL change follows S20 section 3.1.3.3.4 and S21 section 3.1.4.3.4:
a single value becomes a list.

## Known limitations

- Legacy WHITE provider configuration must be migrated explicitly to CLEAR.
  Existing CSAF 2.0 advisories are not automatically relabeled.
- Schema validation alone does not cover all semantic requirements of the
  standard. In particular, successful decoding must not be equated with full
  CSAF compliance.

[S20]: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html
[S21]: https://docs.oasis-open.org/csaf/csaf/v2.1/csd02/csaf-v2.1-csd02.html
[O21]: https://github.com/oasis-tcs/csaf/tree/fd04963f836406b2691c861feb80db58577fc9c7/csaf_2.1/json_schema
[P20]: https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/provider_json_schema.json
[P21]: https://github.com/oasis-tcs/csaf/blob/fd04963f836406b2691c861feb80db58577fc9c7/csaf_2.1/json_schema/provider.json
