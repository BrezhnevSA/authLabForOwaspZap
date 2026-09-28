# DAST launch helpers

- `run-dast-scans-postman-sync-with-discovery.sh` adds `AUTH_MODE=discovery` for 8705-8710 and resets each application's coverage before launching its scan by default.
- `testappauthpostman-with-discovery.json` adds folder `05 - DISCOVERY regression scans`, with reset / scan / coverage requests for each fixture.

The scan creation call remains asynchronous. Run the coverage request only after the corresponding DAST scan has completed.

Example:

```bash
ACTION=scan AUTH_MODE=discovery ONLY=large-bundle-spa \
  PROJECT_ID=42 APP_TOKEN='<token>' \
  ./run-dast-scans-postman-sync-with-discovery.sh
```

## Complex React Auth (8711)

The `*-with-complex-auth` copies include `complex-react-auth` in both FORM (expected failure) and BROWSER (expected pass with `access_token` session-header extraction) target lists. The Postman collection also includes independent reset/expected/coverage controls for port 8711.

## v8 unified coverage

Use `run-dast-scans-postman-sync-with-all-coverage.sh` with the same arguments as the previous runner. It resets the selected fixture's coverage/auth counters before each run by default. For `ACTION=check` it prints compact coverage after the synchronous check; for asynchronous scans it prints the coverage URL to query when the scan completes.

The matching Postman collection is `testappauthpostman-with-all-coverage.json`. Its `07 - ALL testbed coverage` folder contains reset / expected / coverage requests for every port 8101-8711.


## v10 client certificate mode

Client certificates are independent from application authentication. Use `CERT_MODE=certificate`; do not put `certificate` in `AUTH_MODE`. A certificate-only run for the 8712 fixture is:

```bash
ACTION=scan AUTH_MODE=none CERT_MODE=certificate ONLY=client-cert-auth \
  PROJECT_ID=42 APP_TOKEN='<token>' \
  ./run-dast-scans-postman-sync-with-cert-mode.sh
```

`AUTH_MODE=all` covers only authentication mechanisms and does not implicitly enable the client certificate.
