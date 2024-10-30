# Setup provider

The provider is meant to run as an CGI program in an nginx enviroment.

The following instructions are for a Debian 11 server setup
and explain how it works in principle. For a production setup
adjust the examples to your needs.


```(shell)
apt-get install nginx fcgiwrap
cp /usr/share/doc/fcgiwrap/examples/nginx.conf /etc/nginx/fcgiwrap.conf
```
Check if the CGI server and the fcgiwrap Socket are active (running):
```bash
systemctl status fcgiwrap.service
systemctl status fcgiwrap.socket
systemctl is-enabled fcgiwrap.service
systemctl is-enabled fcgiwrap.socket
```
Change the group ownership and the permissions of `/var/www`:
```(shell)
cd /var/www
chgrp -R www-data .
chmod -R g+w .
```

Modify the content of `/etc/nginx/fcgiwrap.conf` like following:

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/setupProviderForITest.sh&lines=25-53) -->
<!-- The below code snippet is automatically added from ../docs/scripts/setupProviderForITest.sh -->
```sh
# Include this file on your nginx.conf to support debian cgi-bin scripts using
# fcgiwrap
location /cgi-bin/ {
  # Disable gzip (it makes scripts feel slower since they have to complete
  # before getting gzipped)
  gzip off;

  # Set the root to /usr/lib (inside this location this means that we are
  # giving access to the files under /usr/lib/cgi-bin)
  root  /usr/lib;

  # Fastcgi socket
  fastcgi_pass  unix:/var/run/fcgiwrap.socket;

  # Fastcgi parameters, include the standard ones
  include /etc/nginx/fastcgi_params;

  fastcgi_split_path_info ^(.+\.go)(.*)$;

  # Adjust non standard parameters (SCRIPT_FILENAME)
  fastcgi_param SCRIPT_FILENAME  /usr/lib$fastcgi_script_name;
  fastcgi_param PATH_INFO $fastcgi_path_info;

  fastcgi_param CSAF_CONFIG /etc/csaf/config.toml;

  fastcgi_param SSL_CLIENT_VERIFY $ssl_client_verify;
  fastcgi_param SSL_CLIENT_S_DN $ssl_client_s_dn;
  fastcgi_param SSL_CLIENT_I_DN $ssl_client_i_dn;
}
```
<!-- MARKDOWN-AUTO-DOCS:END -->
Add to `/etc/nginx/sites-enabled/default`:

```
server {
    root /var/www/html;

      # Other config
      # ...
    location / {
        # Other config
        # ...

        # For atomic directory switches
        disable_symlinks off;

        # directory listings
        autoindex on;
    }

    # enable CGI

    include fcgiwrap.conf;
}
```
Reload nginx to apply the changes (e.g. ```systemctl reload nginx``` on Debian or Ubuntu).

Create `cgi-bin` folder if it not exists: `mkdir -p /usr/lib/cgi-bin/`.

Rename and place the `csaf_provider` binary file under `/usr/lib/cgi-bin/csaf_provider.go`.


Create configuration file under `/etc/csaf/config.toml`
and make sure is has good, restrictive permissions.
It must be readable by the user(id), which the webserver's fastcgi interface
uses to start the CGI-binary with,
as `csaf_provider.go` must be able to read it.

Many systems use `www-data` as user id, so you could do something like

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/setupProviderForITest.sh&lines=84-86) -->
<!-- The below code snippet is automatically added from ../docs/scripts/setupProviderForITest.sh -->
```sh
sudo touch /etc/csaf/config.toml
sudo chgrp www-data /etc/csaf/config.toml
sudo chmod g+r,o-rwx /etc/csaf/config.toml
```
<!-- MARKDOWN-AUTO-DOCS:END -->

**This and the other settings are just examples,**
**please adjust permissions and paths**
**according to your webserver and security needs.**

Here is a minimal example configuration,
which you need to customize for a production setup,
see the [options of `csaf_provider`](https://github.com/gocsaf/csaf/blob/main/docs/csaf_provider.md).

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/setupProviderForITest.sh&lines=94-101) -->
<!-- The below code snippet is automatically added from ../docs/scripts/setupProviderForITest.sh -->
```sh
# upload_signature = true
openpgp_private_key = "/etc/csaf/private.asc"
openpgp_public_key = "/etc/csaf/public.asc"
#tlps = ["green", "red"]
canonical_url_prefix = "https://localhost:8443"
categories = ["Example Company Product A", "expr:document.lang"]
create_service_document = true
#no_passphrase = true
```
<!-- MARKDOWN-AUTO-DOCS:END -->


**Attention:** You need to properly protect the private keys
for the OpenPGP and TLS crypto setup. A few variants are possible
from the software side, but selecting the proper one depends
on your requirements for secure operations and authentication.
Consult an admin with experience for securily operating a web based service
on a GNU/Linux operating system.

Create the folders:
```(shell)
curl https://192.168.56.102/cgi-bin/csaf_provider.go/create --cert-type p12 --cert {clientCertificat.p12}
```
Replace {clientCertificate.p12} with the client certificate file
in pkcs12 format which includes the corresponding key as well.

Or using the uploader:
```(shell)
./csaf_uploader --action create --url https://192.168.56.102/cgi-bin/csaf_provider.go --client-cert {clientCert.crt} --client-key {clientKey.pem}
```

Again replacing `{clientCert.crt}` and `{clientKey.pem}` accordingly.


To let nginx resolves the DNS record `csaf.data.security.domain.tld` to fulfill the [Requirement 10](https://docs.oasis-open.org/csaf/csaf/v2.0/cs01/csaf-v2.0-cs01.html#7110-requirement-10-dns-path) configure a new server block (virtual host) in a separated file under `/etc/nginx/available-sites/{DNSNAME}` like following:
<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/DNSConfigForItest.sh&lines=18-35) -->
<!-- The below code snippet is automatically added from ../docs/scripts/DNSConfigForItest.sh -->
```sh
    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;

        ssl_certificate  '${SSL_CERTIFICATE}'; # e.g. ssl_certificate /etc/ssl/csaf/bundle.crt
        ssl_certificate_key '${SSL_CERTIFICATE_KEY}'; # e.g. ssl_certificate_key /etc/ssl/csaf/testserver-key.pem;

        root /var/www/html;

        server_name ${DNS_NAME}; # e.g. server_name csaf.data.security.domain.tld;

        location = / {
                try_files /.well-known/csaf/provider-metadata.json =404;
        }

        access_log /var/log/nginx/dns-domain_access.log;
        error_log /var/log/nginx/dns-domain_error.log;
}
```
<!-- MARKDOWN-AUTO-DOCS:END -->

Then create a symbolic link to enable the new server block:
```shell
ln -s /etc/nginx/sites-available/{DNSNAME} /etc/nginx/sites-enabled/
```
Replace {DNSNAME} with a server block file name.


### Security considerations

* A good setup variant is to install the provider in a server machine which is
  dedicated to the service, so there are only trustable admin users allowed
  to login. For example a virtual machine can be used.
* Uploading should be done with the uploader and secured by TLS
  client certificates which are individual per person allowed to upload.
  This way it can be traced in the log, who did which uploads.
* For TLS client setups with normal security requirements,
  it should be okay to run a small internal
  certificate authority like the example
  in [development-client-certs.md](development-client-certs.md),
  and import the root certificate on the systems that have users which
  want to upload.
* The single `password` is only for very simple settings, testing or
  (planned feature) as
  additional method in the special situation that TLS client certificates
  are already necessary to access the network system where the uploader is.
