OpenPGP key-pairs for testing only.

Note: as the keypairs are fully public, **do not use them for production**.
Create your own keypair(s) with the security properties and operational
security you need.


### `test1@example.com`

This has been created with:
* gpg (GnuPG) 2.2.19
* (linked with) libgcrypt 1.8.5

```bash
gpg --full-gen-key
RSA (sign only)
Requested keysize is 4096 bits
key does not expire at all
Real name: test1
Email address: test1@example.com
comment:
```

```bash
gpg --export-secret-key --armor test1 > private.asc
gpg --export --armor test1 > public.asc
```
The passphrase for this test OpenPGP key-pair is: `security123`



### `test2@example.org`

Another key-pair for testing **without passphrase** and using the future
OpenPGP algorithms ed25519 and cv25519.

```bash
bash
gpg --version | head -2
gpg (GnuPG) 2.2.27
libgcrypt 1.8.4

export GNUPGHOME=~/tmp/dot-gnupg-20220609
gpg --batch --passphrase '' --quick-gen-key test2@example.org future-default default never
gpg --armor --export test2@example.org >test2_pubkey.asc
gpg --armor --export-secret-key test2@example.org >test2_privatekey.asc
unset GNUPGHOME
```
