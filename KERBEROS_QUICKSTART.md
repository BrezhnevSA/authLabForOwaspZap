# Kerberos quick start for ZAP

## 1. Start the lab

```bash
docker compose --profile kerberos up --build -d
```

The KDC automatically writes all client/server artifacts into:

```text
./kerberos-generated/
```

## 2. Files to pass to ZAP

Use **only** these client-side inputs:

```text
principal: zapuser@ZAP.TEST
password:  ZapTest123!
keytab:    kerberos-generated/zapuser.keytab
```

Choose the Kerberos config based on where ZAP/backend runs.

### ZAP/backend in Docker

Attach it to the lab network:

```bash
docker network connect zap-auth-testbed <zap-container>
```

Use:

```text
config: kerberos-generated/krb5-docker.conf
target: http://kerberos-web.zap.test:8080
```

Mount/copy `krb5-docker.conf` and `zapuser.keytab` into your ZAP/backend container at the paths expected by your implementation.

### ZAP/backend on the host

Use:

```text
config: kerberos-generated/krb5-host.conf
target: http://kerberos-web.zap.test:8602
```

Add this host entry:

```text
127.0.0.1 kerberos-web.zap.test
```

The test KDC is published as `127.0.0.1:10088` TCP+UDP; `krb5-host.conf` already points there.

## 3. Verify generated client keytab

```bash
docker compose --profile kerberos run --rm kerberos-client-check
```

The check performs:

```text
kinit -kt /shared/zapuser.keytab zapuser@ZAP.TEST
        ↓
curl --negotiate http://kerberos-web.zap.test:8080/api/whoami
```

A successful response contains:

```json
{"authenticated": true, "scenario": "kerberos-spnego"}
```

## 4. Do not confuse the two keytabs

```text
zapuser.keytab  -> CLIENT -> ZAP/backend
http.keytab     -> SERVER -> kerberos-web only
```

`http.keytab` contains the service principal `HTTP/kerberos-web.zap.test@ZAP.TEST` and should not be passed to ZAP as its client identity.

## 5. Inspect generated principals without exposing keys

```bash
cat kerberos-generated/zapuser.keytab.txt
cat kerberos-generated/http.keytab.txt
cat kerberos-generated/TESTBED.txt
```
