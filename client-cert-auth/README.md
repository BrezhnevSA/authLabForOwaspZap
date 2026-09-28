# client-cert-auth (8712)

A deterministic mutual-TLS target for testing DAST client-certificate support.

- DAST target: `https://client-cert-auth:8712/`
- Host target: `https://127.0.0.1:8712/`
- Hidden host-only diagnostics: `http://127.0.0.1:9712/__testbed/coverage`
- PFX fixture: `certs/client-auth.pfx`
- PFX certificate index: `0`

The HTTPS listener uses real TLS client authentication (`requestCert=true`, `rejectUnauthorized=true`). A request without a trusted client certificate is rejected during the TLS handshake, before HTTP routing.

The diagnostic/reset API is deliberately served on a different HTTP port (`9712`), so Spider/AJAX Spider scanning the 8712 target cannot discover or attack the reset endpoint.

Regenerate fixture certificates with:

```bash
CLIENT_CERTIFICATE_PASSWORD='<test-password>' ./generate-certs.sh
```

The shell/Postman helpers in the project already point at the bundled fixture. Override the PFX path/password/index with their documented variables if you regenerate it.
