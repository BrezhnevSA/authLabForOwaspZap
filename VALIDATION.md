# Validation performed while building v3

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
