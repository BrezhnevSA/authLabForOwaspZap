# Client certificate / mutual TLS test (8712)

This fixture validates the DAST client-certificate path end to end: multipart upload -> PKCS#12 loading in ZAP -> TLS client certificate selection -> crawling/scanning.

Client certificates are intentionally modeled independently from application authentication. The runner uses `CERT_MODE` for PFX/P12 configuration and `AUTH_MODE` only for form/browser/protocol/script authentication.

## Target

```text
Docker/ZAP network: https://client-cert-auth:8712/
Host mode:          https://127.0.0.1:8712/
```

The listener requires a certificate signed by `certs/testbed-ca.crt`. Without a client certificate, TLS negotiation fails; there is no HTTP 401 fallback.

## Fixture certificate

```text
client-cert-auth/certs/client-auth.pfx
clientCertificateIndex=0
```

The fixture password is configured in the runner/Postman variables and can be overridden. Regenerate all test certificates with:

```bash
cd client-cert-auth
CLIENT_CERTIFICATE_PASSWORD='<new-test-password>' ./generate-certs.sh
```

## DAST multipart fields

The scan request uses:

```text
certificate                 file (.pfx or .p12)
clientCertificatePassword   string
clientCertificateIndex      integer, fixture default 0
```

Example runner invocation:

```bash
ACTION=scan \
AUTH_MODE=none \
CERT_MODE=certificate \
ONLY=client-cert-auth \
PROJECT_ID=<id> \
APP_TOKEN=<token> \
./tools/run-dast-scans-postman-sync-with-cert-mode.sh
```

Override the fixture if needed:

```bash
CLIENT_CERTIFICATE_FILE=/path/to/client.pfx \
CLIENT_CERTIFICATE_PASSWORD='<password>' \
CLIENT_CERTIFICATE_INDEX=0 \
...
```

`AUTH_MODE=none` is used above because the 8712 fixture has no form/browser/token authentication of its own; mTLS is selected independently with `CERT_MODE=certificate`. `AUTH_MODE=all` no longer enables client certificates.

## Coverage

The protected target exposes three business endpoints through links from `/`:

```text
/api/profile
/api/orders
/api/documents
```

`/api/whoami` is diagnostic and is excluded from business discovery coverage.

To preserve real mTLS, diagnostics run on a separate loopback-only port:

```bash
./testbed-coverage.sh reset client-cert-auth
./testbed-coverage.sh show client-cert-auth
```

Equivalent raw URL:

```text
http://127.0.0.1:9712/__testbed/coverage
```

The response includes discovery plus mTLS counters such as successful HTTPS requests, TLS client errors and the last presented certificate subject/issuer/serial.

## Manual verification

Without a certificate, the handshake should fail:

```bash
curl -k https://127.0.0.1:8712/
```

With the bundled PFX it should succeed (supply the fixture password when prompted or via your shell securely):

```bash
curl -k --cert-type P12 --cert client-cert-auth/certs/client-auth.pfx https://127.0.0.1:8712/api/whoami
```

If ZAP validates the target server certificate chain, trust `client-cert-auth/certs/testbed-ca.crt` in the ZAP runtime. Server trust and client-certificate presentation are separate TLS concerns.
