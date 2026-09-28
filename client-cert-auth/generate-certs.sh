#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
mkdir -p certs
PASS="${CLIENT_CERTIFICATE_PASSWORD:-ZapCert123!}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

openssl genrsa -out "$TMP/ca.key" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$TMP/ca.key" -sha256 -days 3650 \
  -subj '/CN=ZAP Auth Testbed CA/O=ZAP Auth Testbed' -out certs/testbed-ca.crt

openssl genrsa -out certs/server.key 2048 >/dev/null 2>&1
openssl req -new -key certs/server.key -subj '/CN=client-cert-auth/O=ZAP Auth Testbed' -out "$TMP/server.csr"
cat > "$TMP/server.ext" <<EOT
subjectAltName=DNS:client-cert-auth,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOT
openssl x509 -req -in "$TMP/server.csr" -CA certs/testbed-ca.crt -CAkey "$TMP/ca.key" -CAcreateserial \
  -out certs/server.crt -days 3650 -sha256 -extfile "$TMP/server.ext"

openssl genrsa -out "$TMP/client.key" 2048 >/dev/null 2>&1
openssl req -new -key "$TMP/client.key" -subj '/CN=zap-client/O=ZAP Auth Testbed' -out "$TMP/client.csr"
cat > "$TMP/client.ext" <<EOT
extendedKeyUsage=clientAuth
keyUsage=digitalSignature,keyEncipherment
EOT
openssl x509 -req -in "$TMP/client.csr" -CA certs/testbed-ca.crt -CAkey "$TMP/ca.key" -CAcreateserial \
  -out certs/client-auth.crt -days 3650 -sha256 -extfile "$TMP/client.ext"

openssl pkcs12 -export \
  -inkey "$TMP/client.key" \
  -in certs/client-auth.crt \
  -certfile certs/testbed-ca.crt \
  -name zap-client \
  -out certs/client-auth.pfx \
  -passout "pass:${PASS}"

chmod 600 certs/server.key certs/client-auth.pfx
printf 'Generated:\n  certs/client-auth.pfx\n  certs/testbed-ca.crt\n  certs/server.crt\n  certs/server.key\n'
