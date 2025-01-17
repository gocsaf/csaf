## csaf_validator

is a tool to validate local advisories files against the JSON Schema and an optional remote validator.

### Exit codes

If no fatal error occurs the program will exit with an exit code `n` with the following conditions:

- `n == 0`: all valid
- `(n & 1) > 0`: a general error occurred, all other flags are unset (see logs for more information)
- `(n & 2) > 0`: schema validation failed
- `(n & 4) > 0`: no remote validator configured
- `(n & 8) > 0`: failure in remote validation

### Usage

```
csaf_validator [OPTIONS] files...

Application Options:
      --version                   Display version of the binary
      --validator=URL             URL to validate documents remotely
      --validator_cache=FILE       FILE to cache remote validations
      --validator_preset=          One or more presets to validate remotely (default: mandatory)
      -o AMOUNT, --output=AMOUNT  If a remote validator was used, display the results in JSON format

AMOUNT:
 all: Print the entire JSON output
 important: Print the entire JSON output but omit all tests without errors, warnings and infos.
 short: Print only the result, errors, warnings and infos.

Help Options:
  -h, --help                      Show this help message
```
