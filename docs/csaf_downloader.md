## csaf_downloader

A tool to download CSAF documents from CSAF providers.

### Usage

```
csaf_downloader [OPTIONS] domain...

Application Options:
  -d, --directory=DIR                            DIRectory to store the downloaded files in
      --insecure                                 Do not check TLS certificates from provider
      --ignore_sigcheck                          Ignore signature check results, just warn on mismatch
      --client_cert=CERT-FILE                    TLS client certificate file (PEM encoded data)
      --client_key=KEY-FILE                      TLS client private key file (PEM encoded data)
      --client_passphrase=PASSPHRASE             Optional passphrase for the client cert (limited, experimental, see doc)
      --version                                  Display version of the binary
  -n, --no_store                                 Do not store files
  -r, --rate=                                    The average upper limit of https operations per second (defaults to unlimited)
  -w, --worker=NUM                               NUMber of concurrent downloads (default: 2)
  -t, --time_range=RANGE                         RANGE of time from which advisories to download
  -f, --folder=FOLDER                            Download into a given subFOLDER
  -i, --ignore_pattern=PATTERN                   Do not download files if their URLs match any of the given PATTERNs
  -H, --header=                                  One or more extra HTTP header fields
      --enumerate_pmd_only                       If this flag is set to true, the downloader will only enumerate valid provider metadata files, but not download documents
      --validator=URL                            URL to validate documents remotely
      --validator_cache=FILE                     FILE to cache remote validations
      --validator_preset=PRESETS                 One or more PRESETS to validate remotely (default: [mandatory])
  -m, --validation_mode=MODE[strict|unsafe]      MODE how strict the validation is (default: strict)
      --forward_url=URL                          URL of HTTP endpoint to forward downloads to
      --forward_header=                          One or more extra HTTP header fields used by forwarding
      --forward_queue=LENGTH                     Maximal queue LENGTH before forwarder (default: 5)
      --forward_insecure                         Do not check TLS certificates from forward endpoint
      --log_file=FILE                            FILE to log downloading to (default: downloader.log)
      --log_level=LEVEL[debug|info|warn|error]   LEVEL of logging details (default: info)
  -c, --config=TOML-FILE                         Path to config TOML file

Help Options:
  -h, --help                                     Show this help message
```

Will download all CSAF documents for the given _domains_, by trying each as a CSAF provider.

If no user agent is specified with `--header=user-agent:custom-agent/1.0` then the default agent in the form of `csaf_distribution/VERSION` is sent.

If a _domain_ starts with `https://` it is instead considered a direct URL to the `provider-metadata.json` and downloading procedes from there.

Increasing the number of workers opens more connections to the web servers
to download more advisories at once. This may improve the overall speed of the download.
However, since this also increases the load on the servers, their administrators could
have taken countermeasures to limit this.

If no config file is explictly given the follwing places are searched for a config file:

```
~/.config/csaf/downloader.toml
~/.csaf_downloader.toml
csaf_downloader.toml
```

with `~` expanding to `$HOME` on unixoid systems and `%HOMEPATH` on Windows systems.

Supported options in config files:

```
# directory         # not set by default
insecure            = false
# client_cert       # not set by default
# client_key        # not set by default
# client_passphrase # not set by default
ignoresigcheck      = false
# rate              # set to unlimited
worker              = 2
# time_range        # not set by default
# folder            # not set by default
# ignore_pattern    # not set by default
# header            # not set by default
# validator         # not set by default
# validator_cache   # not set by default
validator_preset    = ["mandatory"]
validation_mode     = "strict"
# forward_url       # not set by default
# forward_header    # not set by default
forward_queue       = 5
forward_insecure    = false
```

If the `folder` option is given all the advisories are stored in a subfolder
of this name. Otherwise the advisories are each stored in a folder named
by the year they are from.

You can ignore certain advisories while downloading by specifying a list
of regular expressions[^1] to match their URLs by using the `ignorepattern`
option.

E.g. `-i='.*white.*' -i='*.red.*'` will ignore files which URLs contain
the sub strings **white** or **red**.
In the config file this has to be noted as:

```
ignorepattern = [".*white.*", ".*red.*"]
```

#### Timerange option

The `timerange` parameter enables downloading advisories which last changes falls
into a given intervall. There are three possible notations:

1. Relative. If the given string follows the rules of a
   [Go duration](https://pkg.go.dev/time@go1.20.6#ParseDuration),
   the time interval from now going back that duration is used.
   In extension to this the suffixes 'd' for days, 'M' for month
   and 'y' for years are recognized. In these cases only integer
   values are accepted without any fractions.
   Some examples:

   - `"3h"` means downloading the advisories that have changed in the last three hours.
   - `"30m"` .. changed within the last thirty minutes.
   - `"3M2m"` .. changed within the last three months and two minutes.
   - `"2y"` .. changed within the last two years.

2. Absolute. If the given string is an RFC 3339 date timestamp
   the time interval between this date and now is used.
   E.g. `"2006-01-02"` means that all files between 2006 January 2nd and now going to being
   downloaded.
   Accepted patterns are:

   - `"2006-01-02T15:04:05Z"`
   - `"2006-01-02T15:04:05+07:00"`
   - `"2006-01-02T15:04:05-07:00"`
   - `"2006-01-02T15:04:05"`
   - `"2006-01-02T15:04"`
   - `"2006-01-02T15"`
   - `"2006-01-02"`
   - `"2006-01"`
   - `"2006"`

   Missing parts are set to the smallest value possible in that field.

3. Range. Same as 2 but separated by a `,` to span an interval. e.g `2019,2024`
   spans an interval from 1st January 2019 to the 1st January of 2024.

All interval boundaries are inclusive.

#### Forwarding

The downloader is able to forward downloaded advisories and their checksums,
OpenPGP signatures and validation results to an HTTP endpoint.  
The details of the implemented API are described [here](https://github.com/mfd2007/csaf_upload_interface).  
**Attention** This is a work in progress. There is
no production ready server which implements this protocol.
The server in the linked repository is currently for development and testing only.

#### beware of client cert passphrase

The `client-passphrase` option implements a legacy private
key protection mechanism based on RFC 1423, see
[DecryptPEMBlock](https://pkg.go.dev/crypto/x509@go1.20.6#DecryptPEMBlock).
Thus it considered experimental and most likely to be removed
in a future release. Please only use this option, if you fully understand
the security implications!
Note that for fully automated processes, it usually does not make sense
to protect the client certificate's private key with a passphrase.
Because the passphrase has to be accessible to the process anyway to run
unattented. In this situation the processing environment should be secured
properly instead.

[^1]: Accepted syntax is described [here](https://github.com/google/re2/wiki/Syntax).
