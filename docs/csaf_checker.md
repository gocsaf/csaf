## csaf_checker

### Usage

```
Usage:
  csaf_checker [OPTIONS] domain...

Application Options:
  -o, --output=REPORT-FILE              File name of the generated report
  -f, --format=[json|html]              Format of report (default: json)
      --insecure                        Do not check TLS certificates from provider
      --client_cert=CERT-FILE           TLS client certificate file (PEM encoded data)
      --client_key=KEY-FILE             TLS client private key file (PEM encoded data)
      --client_passphrase=PASSPHRASE    Optional passphrase for the client cert (limited, experimental, see downloader doc)
      --version                         Display version of the binary
  -v, --verbose                         Verbose output
  -r, --rate=                           The average upper limit of https operations per second (defaults to unlimited)
  -t, --time_range=RANGE                RANGE of time from which advisories to download
  -i, --ignore_pattern=PATTERN          Do not download files if their URLs match any of the given PATTERNs
  -H, --header=                         One or more extra HTTP header fields
      --validator=URL                   URL to validate documents remotely
      --validator_cache=FILE            FILE to cache remote validations
      --validator_preset=               One or more presets to validate remotely (default: [mandatory])
  -c, --config=TOML-FILE                Path to config TOML file

Help Options:
  -h, --help                            Show this help message
```

Will check all given _domains_, by trying each as a CSAF provider.

If no user agent is specified with `--header=user-agent:custom-agent/1.0` then the default agent in the form of `csaf_distribution/VERSION` is sent.

If a _domain_ starts with `https://` it is instead considered a direct URL to the `provider-metadata.json` and checking proceeds from there.

If no config file is explictly given the follwing places are searched for a config file:

```
~/.config/csaf/checker.toml
~/.csaf_checker.toml
csaf_checker.toml
```

with `~` expanding to `$HOME` on unixoid systems and `%HOMEPATH` on Windows systems.
Supported options in config files:

```
output              = ""
format              = "json"
insecure            = false
# client_cert       # not set by default
# client_key        # not set by default
# client_passphrase # not set by default
verbose             = false
# rate              # not set by default
# time_range         # not set by default
# header            # not set by default
# validator         # not set by default
# validator_cache   # not set by default
validator_preset    = ["mandatory"]
```

Usage example:
`./csaf_checker example.com -f html --rate=5.3 -H apikey:SECRET -o check-results.html`

Each performed check has a return type of either 0,1 or 2:

```
type 0: success
type 1: warning
type 2: error
```

The checker result is a success if no checks resulted in type 2, and a failure otherwise.

The option `timerange` allows to only check advisories from a given time
interval. It can only be given once. See the
[downloader documentation](csaf_downloader.md#timerange-option) for details.

Some providers may limit the rate of requests that may be sent to retrieve advisories.
This may cause the checker to be unable to retrieve all advisories. In this case,
the --rate option can be used to adjust the requests per second
sent by the checker to an acceptable rate.
(The rate that is considered acceptable depends on the provider.)


You can ignore certain advisories while checking by specifying a list
of regular expressions[^1] to match their URLs by using the `ignorepattern`
option.
E.g. `-i='.*white.*' -i='*.red.*'` will ignore files which URLs contain
the sub strings **white** or **red**.
In the config file this has to be noted as:

```
ignorepattern = [".*white.*", ".*red.*"]
```

### Remarks

The `role` given in the `provider-metadata.json` is not
yet considered to change the overall result,
see <https://github.com/gocsaf/csaf/issues/221> .

If a provider hosts one or more advisories with a TLP level of AMBER or RED, then these advisories must be access protected.
To check these advisories, authorization can be given via custom headers or certificates.
The authorization method chosen needs to grant access to all advisories, as otherwise the
checker will be unable to check the advisories it doesn't have permission for, falsifying the result.

[^1]: Accepted syntax is described [here](https://github.com/google/re2/wiki/Syntax).
