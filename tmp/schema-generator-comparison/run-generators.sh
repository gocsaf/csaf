#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

set -u

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK="$ROOT/tmp/schema-generator-comparison"
INPUT="$WORK/input"
OUTPUT="$WORK/output"
LOGS="$WORK/logs"
UID_GID="$(id -u):$(id -g)"

mkdir -p "$INPUT" "$OUTPUT" "$LOGS"
for log in schema-preparation go-jsonschema quicktype modelina schemagen esdigo \
    christopherdavenport-jsonschema emersion-go-jsonschema environment; do
    : >"$LOGS/$log.txt"
done

run() {
    local transcript=$1
    local name=$2
    shift 2
    {
        printf '\n===== %s =====\n' "$name"
        printf 'command:'
        printf ' %q' "$@"
        printf '\n\n'
    } | tee -a "$transcript"

    set +e
    "$@" 2>&1 | tee -a "$transcript"
    local status=${PIPESTATUS[0]}
    set -e
    printf '\nexit status: %d\n' "$status" | tee -a "$transcript"
}

run "$LOGS/schema-preparation.txt" "prepare pinned schema input" \
    python3 "$ROOT/internal/generate/prepare_schema.py" \
    "https://raw.githubusercontent.com/oasis-tcs/csaf/fd04963f836406b2691c861feb80db58577fc9c7/csaf_2.1/json_schema" \
    "$INPUT"

cp "$ROOT/csaf/v21/schema/rolie-feed.json" "$INPUT/rolie-feed.json"

run "$LOGS/go-jsonschema.txt" "go-jsonschema v0.24.1 models only" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work golang:1.26.5 \
    sh -c 'go run github.com/atombender/go-jsonschema@v0.24.1 --only-models --tags json --capitalization ID --capitalization URI --capitalization URL --capitalization CVSS --capitalization CVE --capitalization CSAF --capitalization SSVC --capitalization EPSS --capitalization CPE --capitalization SBOM --capitalization TLP --capitalization CWE --schema-root-type=https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json=CSAF -p comparison -o tmp/schema-generator-comparison/output/go-jsonschema-models.go tmp/schema-generator-comparison/input/csaf.json https://www.first.org/cvss/cvss-v3.0.json https://www.first.org/cvss/cvss-v3.1.json'

run "$LOGS/go-jsonschema.txt" "compile go-jsonschema v0.24.1 models-only output" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work/tmp/schema-generator-comparison/output golang:1.26.5 \
    sh -c 'gofmt -w go-jsonschema-models.go && go test go-jsonschema-models.go'

run "$LOGS/go-jsonschema.txt" "go-jsonschema v0.24.1 with generated validation" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work golang:1.26.5 \
    sh -c 'go run github.com/atombender/go-jsonschema@v0.24.1 --tags json --capitalization ID --capitalization URI --capitalization URL --capitalization CVSS --capitalization CVE --capitalization CSAF --capitalization SSVC --capitalization EPSS --capitalization CPE --capitalization SBOM --capitalization TLP --capitalization CWE --schema-root-type=https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json=CSAF -p comparison -o tmp/schema-generator-comparison/output/go-jsonschema-validation.go tmp/schema-generator-comparison/input/csaf.json https://www.first.org/cvss/cvss-v3.0.json https://www.first.org/cvss/cvss-v3.1.json'

run "$LOGS/go-jsonschema.txt" "compile go-jsonschema v0.24.1 validation output" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work/tmp/schema-generator-comparison/output golang:1.26.5 \
    sh -c 'gofmt -w go-jsonschema-validation.go && go test go-jsonschema-validation.go'

run "$LOGS/quicktype.txt" "quicktype 26.0.0" \
    docker run --rm --user "$UID_GID" -e npm_config_cache=/tmp/npm \
    -v "$ROOT:/work" -w /work node:24-bookworm \
    sh -c 'npx --yes quicktype@26.0.0 --lang go --src-lang schema --package comparison --out tmp/schema-generator-comparison/output/quicktype.go tmp/schema-generator-comparison/input/csaf.json'

run "$LOGS/modelina.txt" "Modelina CLI 5.10.1" \
    docker run --rm --user "$UID_GID" -e npm_config_cache=/tmp/npm \
    -v "$ROOT:/work" -w /work node:24-bookworm \
    sh -c 'npx --yes @asyncapi/modelina-cli@5.10.1 generate golang tmp/schema-generator-comparison/input/csaf.json --packageName comparison --output tmp/schema-generator-comparison/output/modelina'

run "$LOGS/schemagen.txt" "schemagen 0.0.8" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work golang:1.26.5 \
    sh -c 'go run github.com/mirpo/schemagen@v0.0.8 generate tmp/schema-generator-comparison/input/csaf.json --out-go tmp/schema-generator-comparison/output/schemagen --go-package comparison'

run "$LOGS/schemagen.txt" "compile schemagen 0.0.8 output" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work/tmp/schema-generator-comparison/output/schemagen golang:1.26.5 \
    sh -c 'gofmt -w . && go test *.go'

run "$LOGS/esdigo.txt" "esdigo 0.4.1" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work golang:1.26.5 \
    sh -c 'go run github.com/binadel/esdigo/gen/cmd/esdigo-gen@v0.4.1 -pkg comparison -name CSAF -o tmp/schema-generator-comparison/output/esdigo.go tmp/schema-generator-comparison/input/csaf.json'

run "$LOGS/christopherdavenport-jsonschema.txt" "ChristopherDavenport/jsonschema v0.0.5" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work golang:1.26.5 \
    sh -c 'go run github.com/ChristopherDavenport/jsonschema/cmd/jsonschema-gen@v0.0.5 -package comparison -root CSAF -o tmp/schema-generator-comparison/output/davenport.go tmp/schema-generator-comparison/input/csaf.json'

run "$LOGS/christopherdavenport-jsonschema.txt" "ChristopherDavenport/jsonschema v0.0.5 ROLIE" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work golang:1.26.5 \
    sh -c 'go run github.com/ChristopherDavenport/jsonschema/cmd/jsonschema-gen@v0.0.5 -package comparison -root ROLIEFeed -o tmp/schema-generator-comparison/output/davenport-rolie.go tmp/schema-generator-comparison/input/rolie-feed.json'

run "$LOGS/christopherdavenport-jsonschema.txt" "compile ChristopherDavenport ROLIE output" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work/tmp/schema-generator-comparison/output golang:1.26.5 \
    sh -c 'gofmt -w davenport-rolie.go && go test davenport-rolie.go'

run "$LOGS/emersion-go-jsonschema.txt" "emersion/go-jsonschema revision a828df1" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work golang:1.26.5 \
    sh -c 'mkdir -p tmp/schema-generator-comparison/output/emersion && go run codeberg.org/emersion/go-jsonschema/cmd/jsonschemagen@a828df140a57 -s tmp/schema-generator-comparison/input/csaf.json -o tmp/schema-generator-comparison/output/emersion/csaf.go -n comparison'
