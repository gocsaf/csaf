<!--
 This file is Free Software under the Apache-2.0 License
 without warranty, see README.md and LICENSES/Apache-2.0.txt for details.

 SPDX-License-Identifier: Apache-2.0

 SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
 Software-Engineering: 2024 Intevation GmbH <https://intevation.de>
-->



# csaf

Tools and Go library for [CSAF](https://csaf.io).

Includes a **trusted provider**, uploader, checker, aggregator,
**downloader** and validator.
Version 5 adds support for CSAF 2.1 alongside
[CSAF 2.0 and its errata](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html).
Support differs by tool as described below.

Powers
[ISDuBA](https://github.com/ISDuBA/ISDuBA),
[Online CSAF Provider Check](https://check.provider.csaf.dev/)
and others.


## Tools for users
### [csaf_downloader](docs/csaf_downloader.md)
is a tool for downloading CSAF 2.0 and 2.1 advisories from a provider.
Use `--csaf_version=2.0` or `--csaf_version=2.1` to select a provider metadata version.
Can be used for automated forwarding of CSAF documents.

### [csaf_validator](docs/csaf_validator.md)
is a tool to validate local CSAF 2.0 and 2.1 advisory files against the JSON Schema
selected by their `document.csaf_version` and an optional remote validator.
Remote validation is only supported for CSAF 2.0, not for CSAF 2.1.

## Tools for advisory providers

### [csaf_provider](docs/csaf_provider.md)
is an implementation of the role CSAF Trusted Provider, also offering
a simple HTTPS based management service.
It can serve CSAF 2.0, CSAF 2.1, or both in separate version trees.
The default remains CSAF 2.0. See the [provider options](docs/csaf_provider.md#provider-options)
for `csaf_versions`, `version_folders` and `authoritative_version`.

### [csaf_uploader](docs/csaf_uploader.md)
is a command line tool to upload CSAF 2.0 and 2.1 documents to the `csaf_provider`.
TLP labels include `white` for CSAF 2.0 and `clear` and `amber+strict` for CSAF 2.1.

### [csaf_checker](docs/csaf_checker.md)
is a tool for testing a CSAF Trusted Provider according to [Section 7 of the CSAF standard](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#7-distributing-csaf-documents).
Its distribution checks remain based on CSAF 2.0, including directory discovery
and TLP checks. It does not provide a complete CSAF 2.1 conformance check.

### [csaf_aggregator](docs/csaf_aggregator.md)
is a CSAF Aggregator, to list or mirror providers.
Its generated `aggregator.json` and ROLIE entry formats remain based on CSAF 2.0.
Full CSAF 2.1 aggregation is not yet supported.


## Use as Go library

The modules of this repository can be used as library by other Go applications. [ISDuBA](https://github.com/ISDuBA/ISDuBA) does so, for example.
But there is only limited support and thus it is _not officially supported_.
There are plans to change this without a concrete schedule within a future major release, e.g. see [#367](https://github.com/gocsaf/csaf/issues/367).

Initially envisioned as a toolbox, it was not constructed as a library,
and to name one issue, exposes too many functions.
This leads to problems like [#634](https://github.com/gocsaf/csaf/issues/634), where we have to accept that with 3.2.0 there was an unintended API change.

### [examples](./examples/README.md)
are small examples of how to use `github.com/gocsaf/csaf` as an API. Currently this is a work in progress.


## Setup
Binaries for the server side are only available and tested
for GNU/Linux-Systems, e.g. Ubuntu LTS.
They are likely to run on similar systems when build from sources.

The windows binary package only includes
`csaf_downloader`, `csaf_validator`, `csaf_checker` and `csaf_uploader`.

The MacOS binary archives come with the same set of client tools
and are _community supported_. Which means:
while they are expected to run fine,
they are not at the same level of testing and maintenance
as the Windows and GNU/Linux binaries.


### Prebuild binaries

Download the binaries from the most recent release assets on Github.


### Build from sources

- Needs a [supported version](docs/Development.md) of **Go** to be installed.
  [Go installation](https://go.dev/doc/install)

- Clone the repository `git clone https://github.com/gocsaf/csaf.git `

- Build Go components Makefile supplies the following targets:
	- Build for GNU/Linux system: `make build_linux`
    - Build for Windows system (cross build): `make build_win`
    - Build for macOS system on Intel Processor (AMD64) (cross build): `make build_mac_amd64`
    - Build for macOS system on Apple Silicon (ARM64) (cross build): `make build_mac_arm64`
    - Build For GNU/Linux, macOS and Windows: `make build`
	- Build from a specific git tag by passing the intended tag to the `BUILDTAG` variable.
	   E.g. `make BUILDTAG=v1.0.0 build` or `make BUILDTAG=1 build_linux`.
     The special value `1` means checking out the highest git tag for the build.
    - Remove the generated binaries und their directories: `make mostlyclean`

Binaries will be placed in directories named like `bin-linux-amd64/` and `bin-windows-amd64/`.

### Setup (Trusted Provider)

- [Install](https://nginx.org/en/docs/install.html) **nginx**
- To install a TLS server certificate on nginx see [docs/install-server-certificate.md](docs/install-server-certificate.md)
- To configure nginx see [docs/provider-setup.md](docs/provider-setup.md)
- To configure nginx for client certificate authentication see [docs/client-certificate-setup.md](docs/client-certificate-setup.md)

### Development

For further details of the development process consult our [development page](./docs/Development.md).

## Previous repo URLs

> [!NOTE]
> To avoid future breakage, if you have `csaf-poc` in some of your URLs:
> 1. Adjust your HTML links.
> 2. Adjust your go module paths, see [#579](https://github.com/gocsaf/csaf/issues/579#issuecomment-2497244379).
>
> (This repository was moved here from https://github.com/csaf-poc/csaf_distribution on 2024-10-28. The old one is deprecated and redirection will be switched off sometime in 2025.)

## License

- `csaf` is licensed as Free Software under the terms of the [Apache License, Version 2.0](./LICENSES/Apache-2.0.txt).

- See the specific source files
  for details, the license itself can be found in the directory `LICENSES/`.

- Contains third party Free Software components under licenses that to our best knowledge are compatible at time of adding the dependency, [3rdpartylicenses.md](3rdpartylicenses.md) has the details.

- Check the source file of each schema under `csaf/schema/` and `csaf/v21/schema/`
  to see the source and license of each one.
