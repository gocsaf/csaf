#!/bin/sh

# Script to generate the certificates used for testing.

set -e

cd "$(dirname "$0")"

## -- Generate password protected cert

# Create configuration file
cat > cert.conf << 'EOF'
[req]
default_bits = 3072
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = csaf.test
O = CSAF
OU = CSAF Distribution
C = DE

[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = OCSPSigning, clientAuth, serverAuth

subjectAltName = @alt_names

[alt_names]
DNS.1 = csaf.test
DNS.2 = localhost
DNS.3 = *.csaf.test
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate private key
openssl genrsa -out temp_private.key 3072

# Create certificate signing request
openssl req -new -key temp_private.key -out temp_cert.csr -config cert.conf

# Generate certificate
openssl x509 -req -in temp_cert.csr -signkey temp_private.key -out cert.crt -days 36500 -extensions v3_req -extfile cert.conf

# Create encrypted private key with passphrase "qwer"
openssl rsa -in temp_private.key -out privated.pem -aes256 -passout pass:qwer -traditional

## -- Generate NOT password protected client cert

# Create configuration file
cat > cert.conf << 'EOF'
[req]
default_bits = 3072
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = Tester
O = CSAF Tools Development (internal)
C = DE

[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Generate private key
openssl genrsa -out testclientkey.pem 3072

# Create certificate signing request
openssl req -new -key testclientkey.pem -out temp_cert.csr -config cert.conf

# Generate certificate
openssl x509 -req -in temp_cert.csr -signkey testclientkey.pem -out testclient.crt -days 36500 -extensions v3_req -extfile cert.conf


## -- Clean up
rm temp_private.key temp_cert.csr cert.conf
