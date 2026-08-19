#!/bin/sh
set -eu

export KRB5_CONFIG=/shared/krb5-docker.conf
kdestroy >/dev/null 2>&1 || true

# Verify exactly the client keytab intended for ZAP, not only password auth.
kinit -V -kt /shared/zapuser.keytab zapuser@ZAP.TEST
klist

curl --fail --silent --show-error --retry 20 --retry-connrefused --retry-delay 1 --negotiate -u : \
  http://kerberos-web.zap.test:8080/api/whoami
printf '\n'
