# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

"""Download the pinned OASIS schemas and optionally their external references."""

import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import quote, urldefrag, urljoin, urlsplit
from urllib.request import urlopen

SCHEMA_FILES = (
    "aggregator.json",
    "csaf.json",
    "extension-content.json",
    "extension-metadata.json",
    "extension-metaschema.json",
    "meta.json",
    "provider.json",
)
HTTP_TIMEOUT_SECONDS = 30
JSON_SCHEMA_DIALECT_PREFIXES = (
    "http://json-schema.org/",
    "https://json-schema.org/",
)


def fetch(uri: str) -> bytes:
    with urlopen(uri, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return response.read()


def replace_references(value: Any, replacements: dict[str, str]) -> set[str]:
    """Find and replace known $refs anywhere in a schema."""
    replaced: set[str] = set()
    if isinstance(value, list):
        for item in value:
            replaced.update(replace_references(item, replacements))
    elif isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str) and reference in replacements:
            value["$ref"] = replacements[reference]
            replaced.add(reference)
        for item in value.values():
            replaced.update(replace_references(item, replacements))
    return replaced


def replace_expected_references(value: Any, replacements: dict[str, str]) -> None:
    """Replace every occurrence and fail if an expected $ref was not found."""
    missing = replacements.keys() - replace_references(value, replacements)
    if missing:
        msg = f"expected references not found: {', '.join(sorted(missing))}"
        raise ValueError(msg)


def patch_property_references(schemas: dict[str, Any]) -> None:
    """Expose property references through $defs for go-jsonschema."""
    csaf = schemas["csaf.json"]
    provider = schemas["provider.json"]
    aggregator = schemas["aggregator.json"]
    extension_content = schemas["extension-content.json"]
    extension_metadata = schemas["extension-metadata.json"]

    csaf_document = csaf["properties"]["document"]["properties"]
    provider_definitions = provider["$defs"]
    provider_properties = provider["properties"]
    provider_definitions["publisher_t"] = deepcopy(csaf_document["publisher"])
    provider_definitions["tlp_label_t"] = deepcopy(csaf_document["distribution"]["properties"]["tlp"]["properties"]["label"])
    provider_definitions["role_t"] = deepcopy(provider_properties["role"])
    provider_definitions["canonical_url_t"] = deepcopy(provider_properties["canonical_url"])

    csaf_schema = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json"
    provider_schema = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/provider.json"

    extension_content_schema = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/extension-content.json"
    extension_metaschema = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/extension-metaschema.json"
    tlp_label = f"{csaf_schema}#/properties/document/properties/distribution/properties/tlp/properties/label"
    replace_expected_references(
        provider,
        {
            f"{csaf_schema}#/properties/document/properties/publisher": ("#/$defs/publisher_t"),
            tlp_label: "#/$defs/tlp_label_t",
        },
    )
    replace_expected_references(
        aggregator,
        {
            f"{provider_schema}#/properties/publisher": ("provider.json#/$defs/publisher_t"),
            f"{provider_schema}#/properties/role": "provider.json#/$defs/role_t",
            f"{provider_schema}#/properties/canonical_url": ("provider.json#/$defs/canonical_url_t"),
            f"{provider_schema}#/$defs/provider_url_t": ("provider.json#/$defs/provider_url_t"),
        },
    )
    replace_expected_references(
        csaf,
        {extension_content_schema: "extension-content.json"},
    )
    replace_expected_references(
        extension_content,
        {f"{extension_metaschema}#/$defs/content_schema_t": ("extension-metaschema.json#/$defs/content_schema_t")},
    )
    replace_expected_references(
        extension_metadata,
        {f"{extension_metaschema}#/$defs/content_schema_t": ("extension-metaschema.json#/$defs/content_schema_t")},
    )


def declared_identifier(document: Any, retrieval_uri: str) -> str:
    if not isinstance(document, dict):
        return retrieval_uri
    identifier = document.get("$id", document.get("id"))
    if not isinstance(identifier, str):
        return retrieval_uri
    return urljoin(retrieval_uri, identifier)


def reference_targets(value: Any, base_uri: str) -> list[str]:
    """Return absolute, fragment-free HTTP resources reached through $ref."""
    targets: list[str] = []
    if isinstance(value, list):
        for item in value:
            targets.extend(reference_targets(item, base_uri))
    elif isinstance(value, dict):
        scoped_base = declared_identifier(value, base_uri)
        reference = value.get("$ref")
        if isinstance(reference, str):
            target = urldefrag(urljoin(scoped_base, reference)).url
            if target.startswith(("https://", "http://")) and not target.startswith(JSON_SCHEMA_DIALECT_PREFIXES):
                targets.append(target)
        for item in value.values():
            targets.extend(reference_targets(item, scoped_base))
    return targets


def external_path(output_directory: Path, uri: str) -> Path:
    parsed = urlsplit(uri)
    parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        msg = f"unsafe path in schema URI {uri}"
        raise ValueError(msg)
    if not parts:
        parts = ["schema.json"]
    if parsed.query:
        last = Path(parts[-1])
        parts[-1] = f"{last.stem}__{quote(parsed.query, safe='')}{last.suffix}"
    return output_directory / "external" / parsed.netloc / Path(*parts)


def download_external_references(
    initial_documents: list[tuple[str, bytes]],
    output_directory: Path,
) -> None:
    known: set[str] = set()
    pending: list[str] = []
    for retrieval_uri, data in initial_documents:
        document = json.loads(data)
        known.add(urldefrag(retrieval_uri).url)
        known.add(urldefrag(declared_identifier(document, retrieval_uri)).url)
        pending.extend(reference_targets(document, retrieval_uri))

    while pending:
        uri = pending.pop(0)
        if uri in known:
            continue
        data = fetch(uri)
        document = json.loads(data)
        known.add(uri)
        known.add(urldefrag(declared_identifier(document, uri)).url)

        destination = external_path(output_directory, uri)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        pending.extend(reference_targets(document, uri))


def prepare_schemas(
    base_url: str,
    output_directory: Path,
    *,
    follow_references: bool,
) -> None:
    base_url = base_url.rstrip("/")
    schemas: dict[str, Any] = {}
    retrieval_uris: dict[str, str] = {}
    for name in SCHEMA_FILES:
        uri = f"{base_url}/{name}"
        data = fetch(uri)
        schemas[name] = json.loads(data)
        retrieval_uris[name] = uri

    patch_property_references(schemas)

    documents: list[tuple[str, bytes]] = []
    for name in SCHEMA_FILES:
        data = (json.dumps(schemas[name], ensure_ascii=False, indent=2) + "\n").encode()
        (output_directory / name).write_bytes(data)
        documents.append((retrieval_uris[name], data))
    if follow_references:
        download_external_references(documents, output_directory)


def main(arguments: list[str]) -> int:
    follow_references = False
    if arguments and arguments[0] == "--follow-references":
        follow_references = True
        arguments = arguments[1:]
    if len(arguments) != 2:
        print(
            "usage: prepare-schema [--follow-references] <schema base URL> <output directory>",
            file=sys.stderr,
        )
        return 2
    prepare_schemas(
        arguments[0],
        Path(arguments[1]),
        follow_references=follow_references,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
