`csaf_provider` implements a CGI interface for webservers
and reads its configuration from a [TOML](https://toml.io/en/) file.
The [setup docs](../README.md#setup-trusted-provider)
explain how to wire this up with nginx and where the config file lives.

When installed, two endpoints are offered,
and you should use the [csaf_uploader](../docs/csaf_uploader.md)
to access them:

### /api/create

Must be called once after all configuration values are set.
It will write the `provider-metadata.json` and may write
or update the`security.txt`.

Once the files exist, they will **not** be overwriten
by additional `create` calls, even if the config values have been changed.
Changes should happen rarely and can be done manually.
Also keep an eye on having the keys in the `.well-known/csaf/openpgp`
folder match the ones mentioned in the `provider-metadata.json`.

### /api/upload
Called for each upload of a document and will update
the CSAF structure in the file system accordingly.


## Provider options

The following example file documents all available configuration options:

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/examples/provider_config.toml) -->
<!-- The below code snippet is automatically added from ../docs/examples/provider_config.toml -->
```toml
# Set the authentication password for accessing the CSAF provider.
# It is essential that you set a secure password between the quotation marks.
# The default being no password set.
#password = ""

# Set the path to the public OpenPGP key.
#openpgp_public_key = "/etc/csaf/openpgp_public.asc"

# Set the path to the private OpenPGP key.
#openpgp_private_key = "/etc/csaf/openpgp_private.asc"

# Specify the root folder.
#folder = "/var/www/"

# Specify the web folder.
#web = "/var/www/html"

# Allow sending a signature with the request.
# An additional input-field in the web interface will be shown
# to let user enter an ascii armored OpenPGP signature.
#upload_signature = false

# Set the beginning of the URL where contents are accessible from the internet.
# If not set, the provider will read from the $SERVER_NAME variable.
# The following shows an example of a manually set prefix:
#canonical_url_prefix  = "https://localhost"

# Require users to use both
# (1) a password and (2) a valid Client Certificate for write access.
#certificate_and_password = false

# Allow the user to send the request without having to send a passphrase
# to unlock the the OpenPGP key.
# If set to true, the input-field in the web interface will be omitted.
#no_passphrase = false

# Make the provider skip the validation of the uploaded CSAF document
# against the JSON schema.
#no_validation = false

# Disable the experimental web interface.
#no_web_ui = true

# Make the provider take the publisher from the CSAF document.
#dynamic_provider_metadata = false

# Set the upload limit size of a file in bytes.
# The default is equivalent to 50 MiB.
#upload_limit =  52428800

# Set the issuer of the CA.
# If set, the provider restricts the writing permission and the
# access to the web-interface to users with the client certificates
# signed with this CA.
# The following shows an example. As default, none is set.
#issuer = "Example Company"

# Make the provider write/update index.txt and changes.csv.
#write_indices = false

# Make the provider write a `CSAF:` entry into `security.txt`.
#write_security = false

# Set the TLP allowed to be send with the upload request
# (one or more of "csaf", "white", "amber", "green", "red").
# The "csaf" entry lets the provider take the value from the CSAF document.
# These affect the list items in the web interface.
#tlps = ["csaf", "white", "amber", "green", "red"]

# Make the provider create a ROLIE service document.
#create_service_document = false

# Make the provider create a ROLIE category document from a list of strings.
# If a list item starts with `expr:`
#   the rest of the string is used as a JsonPath expression
#   to extract a string from the incoming advisories.
# Strings not starting with `expr:` are taken verbatim.
# By default no category documents are created.
# This example provides an overview over the syntax,
# adjust the parameters depending on your setup.
#categories = ["Example Company Product A", "expr:document.lang"]

# Make the provider use a remote validator service. Not used by default.
# This example provides an overview over the syntax,
# adjust the parameters depending on your setup.
#[remote_validator]
#url = "http://localhost:8082"
#presets = ["mandatory"]
#cache = "/var/lib/csaf/validations.db"

[provider_metadata]
# Indicate that aggregators can list us.
list_on_CSAF_aggregators = true
# Indicate that aggregators can mirror us.
mirror_on_CSAF_aggregators = true

# Set the publisher details.
[provider_metadata.publisher]
category = "vendor"
name = "Example Company"
namespace = "https://example.com"
issuing_authority = "We at Example Company are responsible for publishing and maintaining Product Y."
contact_details = "Example Company can be reached at contact_us@example.com, or via our website at https://www.example.com/contact."
```
<!-- MARKDOWN-AUTO-DOCS:END -->


### Experimental web upload interface

There is an experimental upload interface which works with a web browser.
It is disabled by default, as there are known issues, notably:
 * https://github.com/gocsaf/csaf/issues/43
 * https://github.com/gocsaf/csaf/issues/256
