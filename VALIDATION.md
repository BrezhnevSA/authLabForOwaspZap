# Validation performed while building v4

Validated locally in the artifact environment:

- Node syntax: `protocol-auth`, `client-flows`, existing `browser-edge-cases`.
- Python syntax: NTLM server, Kerberos GSSAPI server, existing FastAPI/Django files.
- Go compile/test: existing `go-multistep`.
- JSON/YAML/XML parsing: package manifests, Docker Compose, Spring `pom.xml`.
- All Docker build contexts referenced by Compose exist.
- Functional backend checks passed for:
  - HTTP Basic
  - HTTP Digest
  - Bearer token
  - X-API-Key
  - two custom headers
  - Basic -> form stacked flow
  - modal login backend
  - consent-checkbox backend
  - localStorage JWT backend/token path
  - SSO app -> IdP -> callback session path

Not executable in the artifact environment because Docker is unavailable here:

- complete `docker compose build/up`;
- live NTLM challenge/response against the pyspnego container;
- live MIT KDC + Kerberos/SPNEGO profile.

Those advanced fixtures are included as real protocol implementations, but should be treated as requiring the first run on a Docker host before relying on them for regression gating.

## v4 Kerberos artifact changes

Static validation completed for the self-provisioning Kerberos changes:

- KDC start script now creates/ensures both client and HTTP service principals.
- `zapuser.keytab` is exported with `ktadd -norandkey`, preserving the configured user password.
- `http.keytab` remains separate and server-only.
- Docker and host `krb5.conf` variants are generated automatically.
- KDC port 88 is exposed on host loopback port 10088 for host-side ZAP/backend testing.
- `kerberos-client-check` now authenticates with the generated client keytab.
- generated files are bind-mounted to `./kerberos-generated` instead of hidden in a named Docker volume.

Docker itself is unavailable in the artifact environment, so the first live KDC/SPNEGO startup still needs to be run on a Docker host.
