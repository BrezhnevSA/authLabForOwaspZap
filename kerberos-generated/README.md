# Generated Kerberos files

This directory is populated automatically by:

```bash
docker compose --profile kerberos up --build -d
```

Expected generated files include:

- `zapuser.keytab` — **client keytab to provide to ZAP**
- `http.keytab` — server keytab used only by the test web application
- `krb5-docker.conf` — config for a ZAP/container on `zap-auth-testbed`
- `krb5-host.conf` — config for ZAP running directly on the Docker host
- `krb5.conf` — alias of the Docker-network configuration
- `TESTBED.txt` — credentials, principals, targets, and usage hints
- `kerberos-client.env` — machine-readable values for wiring the fixture into a client
- `*.keytab.txt` — human-readable `klist` inventories (no secret key bytes)

Do not commit or redistribute generated `*.keytab` files outside this disposable test lab.
