# Hostname setup for browser SSO scenarios

If ZAP/browser runs on the host OS and these names do not already resolve to loopback, add:

```text
127.0.0.1 sso-app.localhost
127.0.0.1 sso-idp.localhost
127.0.0.1 customer-app.localhost
127.0.0.1 identity.localhost
```

On Linux this can be done temporarily with:

```bash
printf '%s\n' \
  '127.0.0.1 sso-app.localhost' \
  '127.0.0.1 sso-idp.localhost' \
  '127.0.0.1 customer-app.localhost' \
  '127.0.0.1 identity.localhost' | sudo tee -a /etc/hosts
```

If ZAP runs in Docker, do not add these entries inside the ZAP container. Attach it to the `zap-auth-testbed` network; Docker aliases are already configured.

The Kerberos fixture is designed primarily for Docker-network testing because its KDC and SPN names must remain consistent. Use `kerberos-web.zap.test:8080` from a container attached to `zap-auth-testbed`.
