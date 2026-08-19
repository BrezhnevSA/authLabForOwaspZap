# Hostname setup for browser SSO and Kerberos scenarios

If ZAP/browser runs on the host OS and these names do not already resolve to loopback, add:

```text
127.0.0.1 sso-app.localhost
127.0.0.1 sso-idp.localhost
127.0.0.1 customer-app.localhost
127.0.0.1 identity.localhost
127.0.0.1 kerberos-web.zap.test
```

On Linux this can be done temporarily with:

```bash
printf '%s\n' \
  '127.0.0.1 sso-app.localhost' \
  '127.0.0.1 sso-idp.localhost' \
  '127.0.0.1 customer-app.localhost' \
  '127.0.0.1 identity.localhost' \
  '127.0.0.1 kerberos-web.zap.test' | sudo tee -a /etc/hosts
```

If ZAP runs in Docker, do not add these entries inside the ZAP container. Attach it to the `zap-auth-testbed` network; Docker aliases are already configured.

## Kerberos host mode

When ZAP/backend runs directly on the host, start the Kerberos profile and use:

```text
config: kerberos-generated/krb5-host.conf
keytab: kerberos-generated/zapuser.keytab
target: http://kerberos-web.zap.test:8602
KDC:    127.0.0.1:10088
```

When ZAP/backend runs in Docker on `zap-auth-testbed`, use:

```text
config: kerberos-generated/krb5-docker.conf
keytab: kerberos-generated/zapuser.keytab
target: http://kerberos-web.zap.test:8080
KDC:    kerberos-kdc.zap.test:88
```
