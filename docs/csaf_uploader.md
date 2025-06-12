## csaf_uploader

### Usage

```
csaf_uploader [OPTIONS]

Application Options:
  -a, --action=[upload|create]              Action to perform (default: upload)
  -u, --url=URL                             URL of the CSAF provider (default: https://localhost/cgi-bin/csaf_provider.go)
  -t, --tlp=[csaf|white|green|amber|red]    TLP of the feed (default: csaf)
  -x, --external_signed                     CSAF files are signed externally. Assumes .asc files beside CSAF files.
  -s, --no_schema_check                     Do not check files against CSAF JSON schema locally.
  -k, --key=KEY-FILE                        OpenPGP key to sign the CSAF files
  -p, --password=PASSWORD                   Authentication password for accessing the CSAF provider
  -P, --passphrase=PASSPHRASE               Passphrase to unlock the OpenPGP key
      --client_cert=CERT-FILE.crt           TLS client certificate file (PEM encoded data)
      --client_key=KEY-FILE.pem             TLS client private key file (PEM encoded data)
      --client_passphrase=PASSPHRASE        Optional passphrase for the client cert (limited, experimental, see downloader doc)
  -i, --password_interactive                Enter password interactively
  -I, --passphrase_interactive              Enter OpenPGP key passphrase interactively
      --insecure                            Do not check TLS certificates from provider
  -c, --config=TOML-FILE                    Path to config TOML file
      --version                             Display version of the binary

Help Options:
  -h, --help                                Show this help message
```
E.g. creating the initial directories and files.
This must only be done once, as subsequent `create` calls to the
[csaf_provider](../docs/csaf_provider.md)
may not lead to the desired result.

```bash
./csaf_uploader -a create  -u https://localhost/cgi-bin/csaf_provider.go
```

E.g. uploading a csaf-document

```bash
./csaf_uploader -a upload -I -t white -u https://localhost/cgi-bin/csaf_provider.go  CSAF-document-1.json
```

which asks to enter a password interactively.

To upload an already signed document, use the `-x` option
```bash
# Note: The file CSAF-document-1.json.asc must exist
./csaf_uploader -x -a upload -I -t white -u https://localhost/cgi-bin/csaf_provider.go  CSAF-document-1.json
```

By default csaf_uploader will try to load a config file
from the following places:

```
    "~/.config/csaf/uploader.toml",
    "~/.csaf_uploader.toml",
    "csaf_uploader.toml",
```

The command line options can be written in the config file:
```
action                 = "upload"
url                    = "https://localhost/cgi-bin/csaf_provider.go"
tlp                    = "csaf"
external_signed        = false
no_schema_check        = false
# key                  = "/path/to/openpgp/key/file"       # not set by default
# password             = "auth-key to access the provider" # not set by default
# passphrase           = "OpenPGP passphrase"              # not set by default
# client_cert          = "/path/to/client/cert"            # not set by default
# client_key           = "/path/to/client/cert.key"        # not set by default
# client_passphrase    = "client cert passphrase"          # not set by default
password_interactive   = false
passphrase_interactive = false
insecure               = false
```
