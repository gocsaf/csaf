# SPDX-License-Identifier: Apache-2.0

"""Prepare the checked-in CSAF 2.0 schemas for Go model generation."""

import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

CSAF_ID = "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json"
PROVIDER_ID = "https://docs.oasis-open.org/csaf/csaf/v2.0/provider_json_schema.json"
SCHEMAS = (
    "csaf_json_schema.json",
    "provider_json_schema.json",
    "aggregator_json_schema.json",
    "cvss-v2.0.json",
    "cvss-v3.0.json",
    "cvss-v3.1.json",
)


def replace_reference(value: Any, old: str, new: str) -> int:
    count = 0
    if isinstance(value, dict):
        if value.get("$ref") == old:
            value["$ref"] = new
            count += 1
        for child in value.values():
            count += replace_reference(child, old, new)
    elif isinstance(value, list):
        for child in value:
            count += replace_reference(child, old, new)
    return count


def replace_once(value: Any, old: str, new: str) -> None:
    count = replace_reference(value, old, new)
    if count != 1:
        msg = f"expected one reference to {old}, found {count}"
        raise ValueError(msg)


def prepare(source: Path, destination: Path) -> None:
    schemas = {name: json.loads((source / name).read_text()) for name in SCHEMAS}
    csaf = schemas["csaf_json_schema.json"]
    provider = schemas["provider_json_schema.json"]
    aggregator = schemas["aggregator_json_schema.json"]

    # go-jsonschema only accepts references to definitions in another file.
    publisher = deepcopy(csaf["properties"]["document"]["properties"]["publisher"])
    provider["$defs"]["publisher_t"] = publisher
    provider["$defs"]["role_t"] = deepcopy(provider["properties"]["role"])
    provider["$defs"]["canonical_url_t"] = deepcopy(provider["properties"]["canonical_url"])
    replace_once(
        provider,
        f"{CSAF_ID}#/properties/document/properties/publisher",
        "#/$defs/publisher_t",
    )
    for name in ("publisher", "role", "canonical_url"):
        replace_once(
            aggregator,
            f"{PROVIDER_ID}#/properties/{name}",
            f"provider_json_schema.json#/$defs/{name}_t",
        )

    # Resolve CVSS references to the checked-in copies during generation.
    destination.mkdir(parents=True, exist_ok=True)
    for version in ("2.0", "3.0"):
        schemas[f"cvss-v{version}.json"]["id"] = f"https://www.first.org/cvss/cvss-v{version}.json"
    schemas["cvss-v3.1.json"]["$id"] = "https://www.first.org/cvss/cvss-v3.1.json"
    for version in ("2.0", "3.0", "3.1"):
        name = f"cvss-v{version}.json"
        replace_once(
            csaf,
            f"https://www.first.org/cvss/{name}",
            (destination / name).resolve().as_uri(),
        )

    for name, schema in schemas.items():
        (destination / name).write_text(json.dumps(schema, indent=2) + "\n")


def main(arguments: list[str]) -> int:
    if len(arguments) != 2:
        print("usage: prepare_v20_schema.py <source directory> <output directory>", file=sys.stderr)
        return 2
    prepare(Path(arguments[0]), Path(arguments[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
