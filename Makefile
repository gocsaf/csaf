# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2021 Intevation GmbH <https://intevation.de>
#
# Makefile to build csaf components

SHELL = /bin/bash
BUILD = go build
MKDIR = mkdir -p

.PHONY: build build_linux build_linux_arm64 build_win build_win_arm64 build_mac_amd64 build_mac_arm64 generate_v21 tag_checked_out mostlyclean

PYTHON ?= python3
GENERATOR_VERSION := v0.24.1
OASIS_SCHEMA_BASE := https://raw.githubusercontent.com/oasis-tcs/csaf/fd04963f836406b2691c861feb80db58577fc9c7/csaf_2.1/json_schema
CSAF_SCHEMA_ID := https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json
AGGREGATOR_SCHEMA_ID := https://docs.oasis-open.org/csaf/csaf/v2.1/schema/aggregator.json
PROVIDER_SCHEMA_ID := https://docs.oasis-open.org/csaf/csaf/v2.1/schema/provider.json
EXTENSION_CONTENT_SCHEMA_ID := https://docs.oasis-open.org/csaf/csaf/v2.1/schema/extension-content.json
EXTENSION_METADATA_SCHEMA_ID := https://docs.oasis-open.org/csaf/csaf/v2.1/schema/extension-metadata.json
EXTENSION_METASCHEMA_ID := https://docs.oasis-open.org/csaf/csaf/v2.1/schema/extension-metaschema.json
CVSS_V20_SCHEMA_ID := https://www.first.org/cvss/cvss-v2.0.json?20170531
CVSS_V30_SCHEMA_ID := https://www.first.org/cvss/cvss-v3.0.json?20170531
CVSS_V31_SCHEMA_ID := https://www.first.org/cvss/cvss-v3.1.json?20211103
CVSS_V40_SCHEMA_ID := https://www.first.org/cvss/cvss-v4.0.json?20260226
# Keep the CVSS schemas in one output so go-jsonschema resolves shared type names.
SSVC_V2_SCHEMA_ID := https://certcc.github.io/SSVC/data/schema/v2/SelectionList_2_0_0.schema.json
CAPITALIZATIONS := ID URI URL CVSS CVE CSAF SSVC EPSS CPE SBOM TLP CWE
CAPITALIZATION_FLAGS := $(foreach word,$(CAPITALIZATIONS),--capitalization $(word))

all:
	@echo choose a target from: build build_linux build_linux_arm64 build_win build_win_arm64 build_mac_amd64 build_mac_arm64 mostlyclean
	@echo prepend \`make BUILDTAG=1\` to checkout the highest git tag before building
	@echo or set BUILDTAG to a specific tag

generate_v21:
	@set -eu; \
	model_dir=$$(mktemp -d csaf/v21/model-output.XXXXXX); \
	schema_output=$$(mktemp csaf/v21/schemas_generated.go.XXXXXX); \
	schema_dir=$$(mktemp -d schema-input.XXXXXX); \
	trap 'find "$$model_dir" "$$schema_dir" -type f -delete; rmdir "$$model_dir" "$$schema_dir"; rm -f "$$schema_output"' EXIT; \
	$(PYTHON) ./internal/generate/prepare_schema.py $(OASIS_SCHEMA_BASE) "$$schema_dir"; \
	go run github.com/atombender/go-jsonschema@$(GENERATOR_VERSION) \
		--only-models --tags json $(CAPITALIZATION_FLAGS) \
		--schema-root-type=$(CSAF_SCHEMA_ID)=CSAF \
		--schema-root-type=$(AGGREGATOR_SCHEMA_ID)=Aggregator \
		--schema-root-type=$(PROVIDER_SCHEMA_ID)=Provider \
		--schema-root-type='$(CVSS_V20_SCHEMA_ID)=CVSSV20' \
		--schema-root-type='$(CVSS_V30_SCHEMA_ID)=CVSSV30' \
		--schema-root-type='$(CVSS_V31_SCHEMA_ID)=CVSSV31' \
		--schema-root-type='$(CVSS_V40_SCHEMA_ID)=CVSSV40' \
		--schema-root-type=$(SSVC_V2_SCHEMA_ID)=SSVCV2 \
		--schema-output=$(AGGREGATOR_SCHEMA_ID)="$$model_dir/aggregator_generated.go" \
		--schema-output=$(PROVIDER_SCHEMA_ID)="$$model_dir/provider_generated.go" \
		--schema-output=$(EXTENSION_CONTENT_SCHEMA_ID)="$$model_dir/extension_content_generated.go" \
		--schema-output=$(EXTENSION_METADATA_SCHEMA_ID)="$$model_dir/extension_metadata_generated.go" \
		--schema-output=$(EXTENSION_METASCHEMA_ID)="$$model_dir/extension_metaschema_generated.go" \
		--schema-output='$(CVSS_V20_SCHEMA_ID)='"$$model_dir/cvss_generated.go" \
		--schema-output='$(CVSS_V30_SCHEMA_ID)='"$$model_dir/cvss_generated.go" \
		--schema-output='$(CVSS_V31_SCHEMA_ID)='"$$model_dir/cvss_generated.go" \
		--schema-output='$(CVSS_V40_SCHEMA_ID)='"$$model_dir/cvss_generated.go" \
		--schema-output=$(SSVC_V2_SCHEMA_ID)="$$model_dir/ssvc20_generated.go" \
		-p v21 -o "$$model_dir/csaf_generated.go" \
		"$$schema_dir/meta.json" \
		"$$schema_dir/extension-metaschema.json" \
		"$$schema_dir/extension-content.json" \
		"$$schema_dir/extension-metadata.json" \
		"$$schema_dir/csaf.json" \
		"$$schema_dir/provider.json" \
		"$$schema_dir/aggregator.json" \
		https://www.first.org/cvss/cvss-v3.0.json \
		https://www.first.org/cvss/cvss-v3.1.json; \
	$(PYTHON) ./internal/generate/prepare_model.py "$$model_dir"/*.go; \
	$(PYTHON) ./internal/generate/bundle_schema.py "$$schema_output" "$$schema_dir"/*.json csaf/v21/schema/rolie-feed.json; \
	gofmt -w "$$model_dir"/*.go "$$schema_output"; \
	mv "$$model_dir/aggregator_generated.go" csaf/v21/aggregator_generated.go; \
	mv "$$model_dir/csaf_generated.go" csaf/v21/csaf_generated.go; \
	mv "$$model_dir/cvss_generated.go" csaf/v21/cvss_generated.go; \
	mv "$$model_dir/extension_content_generated.go" csaf/v21/extension_content_generated.go; \
	mv "$$model_dir/extension_metadata_generated.go" csaf/v21/extension_metadata_generated.go; \
	mv "$$model_dir/extension_metaschema_generated.go" csaf/v21/extension_metaschema_generated.go; \
	mv "$$model_dir/provider_generated.go" csaf/v21/provider_generated.go; \
	mv "$$model_dir/ssvc20_generated.go" csaf/v21/ssvc20_generated.go; \
	mv "$$schema_output" csaf/v21/schemas_generated.go; \
	find "$$schema_dir" -type f -delete; \
	rmdir "$$model_dir" "$$schema_dir"; \
	trap - EXIT

# Build all binaries
build: build_linux build_linux_arm64 build_win build_win_arm64 build_mac_amd64 build_mac_arm64

# if BUILDTAG == 1 set it to the highest git tag
ifeq ($(strip $(BUILDTAG)),1)
override BUILDTAG = $(shell git tag --sort=-version:refname | head -n 1)
endif

ifdef BUILDTAG
# add the git tag checkout to the requirements of our build targets
build_linux build_linux_arm64 build_win build_win_arm64 build_mac_amd64 build_mac_arm64: tag_checked_out
endif

tag_checked_out:
	$(if $(strip $(BUILDTAG)),,$(error no git tag found))
	git checkout -q tags/${BUILDTAG}
	@echo Don\'t forget that we are in checked out tag $(BUILDTAG) now.

# use bash shell arithmetic and sed to turn a `git describe` version
# into a semver version. For this we increase the PATCH number, so that
# any commit after a tag is considered newer than the semver from the tag
# without an optional 'v'
# Note we need `--tags` because github releases only create lightweight tags
#   (see feature request https://github.com/github/feedback/discussions/4924).
#   We use `--always` in case of being run as github action with shallow clone.
#   In this case we might in some situations see an error like
#   `/bin/bash: line 1: 2b55bbb: value too great for base (error token is "2b55bbb")`
#   which can be ignored.
GITDESC := $(shell git describe --tags --always --dirty=-modified 2>/dev/null || true)
CURRENT_FOLDER_NAME := $(notdir $(CURDIR))
ifeq ($(strip $(GITDESC)),)
SEMVER := $(CURRENT_FOLDER_NAME)
else
GITDESCPATCH := $(shell echo '$(GITDESC)' | sed -E 's/v?[0-9]+\.[0-9]+\.([0-9]+)[-+]?.*/\1/')
SEMVERPATCH := $(shell echo $$(( $(GITDESCPATCH) + 1 )))
# Hint: The second regexp in the next line only matches
#       if there is a hyphen (`-`) followed by a number,
#       by which we assume that git describe has added a string after the tag
SEMVER := $(shell echo '$(GITDESC)' | sed -E -e 's/^v//' -e 's/([0-9]+\.[0-9]+\.)([0-9]+)(-[1-9].*)/\1$(SEMVERPATCH)\3/' )
endif
testsemver:
	@echo from \'$(GITDESC)\' transformed to \'$(SEMVER)\'


# Set -ldflags parameter to pass the semversion.
LDFLAGS = -ldflags "-X github.com/gocsaf/csaf/v3/util.SemVersion=$(SEMVER)"

# Build binaries and place them under bin-$(GOOS)-$(GOARCH)
# Using 'Target-specific Variable Values' to specify the build target system

build_linux: GOOS=linux
build_linux: GOARCH=amd64

build_win: GOOS=windows
build_win: GOARCH=amd64

build_mac_amd64: GOOS=darwin
build_mac_amd64: GOARCH=amd64

build_mac_arm64: GOOS=darwin
build_mac_arm64: GOARCH=arm64

build_linux_arm64: GOOS=linux
build_linux_arm64: GOARCH=arm64

build_win_arm64: GOOS=windows
build_win_arm64: GOARCH=arm64

build_linux build_linux_arm64 build_win build_win_arm64 build_mac_amd64 build_mac_arm64:
	$(eval BINDIR = bin-$(GOOS)-$(GOARCH)/ )
	$(MKDIR) $(BINDIR)
	env GOARCH=$(GOARCH) GOOS=$(GOOS) $(BUILD) -o $(BINDIR) $(LDFLAGS) -v ./cmd/...


DISTDIR := csaf-$(SEMVER)
dist: build_linux build_linux_arm64 build_win build_win_arm64 build_mac_amd64 build_mac_arm64
	mkdir -p dist
	mkdir -p dist/$(DISTDIR)-windows-amd64/bin-windows-amd64
	mkdir -p dist/$(DISTDIR)-windows-arm64/bin-windows-arm64
	cp README.md dist/$(DISTDIR)-windows-amd64
	cp README.md dist/$(DISTDIR)-windows-arm64
	cp bin-windows-amd64/csaf_uploader.exe bin-windows-amd64/csaf_validator.exe \
	  bin-windows-amd64/csaf_checker.exe bin-windows-amd64/csaf_downloader.exe \
	  dist/$(DISTDIR)-windows-amd64/bin-windows-amd64/
	cp bin-windows-arm64/csaf_uploader.exe bin-windows-arm64/csaf_validator.exe \
	  bin-windows-arm64/csaf_checker.exe bin-windows-arm64/csaf_downloader.exe \
	  dist/$(DISTDIR)-windows-arm64/bin-windows-arm64/
	mkdir -p dist/$(DISTDIR)-windows-amd64/docs
	mkdir -p dist/$(DISTDIR)-windows-arm64/docs
	cp docs/csaf_uploader.md docs/csaf_validator.md docs/csaf_checker.md \
	  docs/csaf_downloader.md dist/$(DISTDIR)-windows-amd64/docs
	cp docs/csaf_uploader.md docs/csaf_validator.md docs/csaf_checker.md \
	  docs/csaf_downloader.md dist/$(DISTDIR)-windows-arm64/docs
	mkdir -p dist/$(DISTDIR)-macos/bin-darwin-amd64 \
		     dist/$(DISTDIR)-macos/bin-darwin-arm64 \
			 dist/$(DISTDIR)-macos/docs
	for f in csaf_downloader csaf_checker csaf_validator csaf_uploader ; do \
		cp bin-darwin-amd64/$$f dist/$(DISTDIR)-macos/bin-darwin-amd64 ; \
		cp bin-darwin-arm64/$$f dist/$(DISTDIR)-macos/bin-darwin-arm64 ; \
		cp docs/$${f}.md dist/$(DISTDIR)-macos/docs ; \
	done
	mkdir dist/$(DISTDIR)-gnulinux-amd64
	mkdir dist/$(DISTDIR)-gnulinux-arm64
	cp -r README.md bin-linux-amd64 dist/$(DISTDIR)-gnulinux-amd64
	cp -r README.md bin-linux-arm64 dist/$(DISTDIR)-gnulinux-arm64
	# adjust which docs to copy
	mkdir -p dist/tmp_docs
	cp -r docs/examples dist/tmp_docs
	cp docs/*.md dist/tmp_docs
	cp -r dist/tmp_docs dist/$(DISTDIR)-gnulinux-amd64/docs
	cp -r dist/tmp_docs dist/$(DISTDIR)-gnulinux-arm64/docs
	rm -rf dist/tmp_docs
	cd dist/ ; zip -r $(DISTDIR)-windows-amd64.zip $(DISTDIR)-windows-amd64/
	cd dist/ ; zip -r $(DISTDIR)-windows-arm64.zip $(DISTDIR)-windows-arm64/
	cd dist/ ; tar -cvmlzf $(DISTDIR)-gnulinux-amd64.tar.gz $(DISTDIR)-gnulinux-amd64/
	cd dist/ ; tar -cvmlzf $(DISTDIR)-gnulinux-arm64.tar.gz $(DISTDIR)-gnulinux-arm64/
	cd dist/ ; tar -cvmlzf $(DISTDIR)-macos.tar.gz $(DISTDIR)-macos

# Remove bin-*-* and dist directories
mostlyclean:
	rm -rf ./bin-*-* dist/
	@echo Files in \`go env GOCACHE\` remain.
