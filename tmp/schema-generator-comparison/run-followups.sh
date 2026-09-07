#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

set -u

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK="$ROOT/tmp/schema-generator-comparison"
INPUT="$WORK/input-with-references"
OUTPUT="$WORK/output"
LOGS="$WORK/logs"
UID_GID="$(id -u):$(id -g)"

mkdir -p "$INPUT" "$OUTPUT" "$LOGS"

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

run "$LOGS/schema-preparation.txt" "prepare pinned schema input including external references" \
    python3 "$ROOT/internal/generate/prepare_schema.py" --follow-references \
    "https://raw.githubusercontent.com/oasis-tcs/csaf/fd04963f836406b2691c861feb80db58577fc9c7/csaf_2.1/json_schema" \
    "$INPUT"

run "$LOGS/schemagen.txt" "schemagen 0.0.8 with all local references" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work golang:1.26.5 \
    sh -c 'go run github.com/mirpo/schemagen@v0.0.8 generate tmp/schema-generator-comparison/input-with-references --out-go tmp/schema-generator-comparison/output/schemagen-with-references --go-package comparison'

run "$LOGS/schemagen.txt" "compile schemagen 0.0.8 output with all local references" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work/tmp/schema-generator-comparison/output/schemagen-with-references golang:1.26.5 \
    sh -c 'gofmt -w . && go test *.go external/**/*.go'

run "$LOGS/esdigo.txt" "esdigo 0.4.1 with all local references" \
    timeout 30s docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work golang:1.26.5 \
    sh -c 'go run github.com/binadel/esdigo/gen/cmd/esdigo-gen@v0.4.1 -pkg comparison -outdir tmp/schema-generator-comparison/output/esdigo-with-references tmp/schema-generator-comparison/input-with-references'

run "$LOGS/emersion-go-jsonschema.txt" "compile emersion/go-jsonschema output" \
    docker run --rm --user "$UID_GID" \
    -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod \
    -v "$ROOT:/work" -w /work/tmp/schema-generator-comparison/output/emersion golang:1.26.5 \
    sh -c 'gofmt -w csaf.go && go test csaf.go'

run "$LOGS/environment.txt" "host Go version" go version

run "$LOGS/environment.txt" "Go container image" \
    docker image inspect golang:1.26.5 --format 'image: {{.Id}}'

run "$LOGS/environment.txt" "Node container image" \
    docker image inspect node:24-bookworm --format 'image: {{.Id}}'

run "$LOGS/environment.txt" "Node and npm versions" \
    docker run --rm node:24-bookworm sh -c 'node --version && npm --version'
