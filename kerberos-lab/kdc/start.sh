#!/bin/sh
set -eu

REALM="ZAP.TEST"
USER_PRINCIPAL="zapuser@${REALM}"
SERVICE_PRINCIPAL="HTTP/kerberos-web.zap.test@${REALM}"
USER_PASSWORD="ZapTest123!"
MASTER_PASSWORD="MasterPass123!"

mkdir -p /shared /var/lib/krb5kdc /etc/krb5kdc
printf '*/admin@ZAP.TEST *\n' > /etc/krb5kdc/kadm5.acl

if [ ! -f /var/lib/krb5kdc/principal ]; then
  echo '[kerberos-kdc] Creating realm ZAP.TEST'
  kdb5_util create -s -P "$MASTER_PASSWORD"
fi

if ! kadmin.local -q "getprinc ${USER_PRINCIPAL}" 2>/dev/null | grep -q '^Principal:'; then
  echo "[kerberos-kdc] Creating client principal ${USER_PRINCIPAL}"
  kadmin.local -q "addprinc -pw ${USER_PASSWORD} ${USER_PRINCIPAL}"
fi

if ! kadmin.local -q "getprinc ${SERVICE_PRINCIPAL}" 2>/dev/null | grep -q '^Principal:'; then
  echo "[kerberos-kdc] Creating HTTP service principal ${SERVICE_PRINCIPAL}"
  kadmin.local -q "addprinc -randkey ${SERVICE_PRINCIPAL}"
fi

# Re-export keytabs on every start without rotating principal keys.
# This makes the files deterministic with respect to the current KDC database
# and keeps the zapuser password valid as well.
rm -f /shared/zapuser.keytab /shared/http.keytab
kadmin.local -q "ktadd -norandkey -k /shared/zapuser.keytab ${USER_PRINCIPAL}"
kadmin.local -q "ktadd -norandkey -k /shared/http.keytab ${SERVICE_PRINCIPAL}"

# Docker-network config: clients resolve kerberos-kdc.zap.test through Compose DNS.
cp /etc/krb5.conf /shared/krb5.conf
cp /etc/krb5.conf /shared/krb5-docker.conf

# Host config: KDC is published by Compose on 127.0.0.1:10088.
cat > /shared/krb5-host.conf <<'KRBEOF'
[libdefaults]
 default_realm = ZAP.TEST
 dns_lookup_realm = false
 dns_lookup_kdc = false
 rdns = false
 forwardable = true

[realms]
 ZAP.TEST = {
  kdc = 127.0.0.1:10088
 }

[domain_realm]
 .zap.test = ZAP.TEST
 zap.test = ZAP.TEST
KRBEOF

cat > /shared/kerberos-client.env <<'ENVEOF'
KRB5_REALM=ZAP.TEST
KRB5_PRINCIPAL=zapuser@ZAP.TEST
KRB5_USERNAME=zapuser
KRB5_PASSWORD=ZapTest123!
KRB5_CLIENT_KEYTAB=zapuser.keytab
KRB5_SERVICE_PRINCIPAL=HTTP/kerberos-web.zap.test@ZAP.TEST
KRB5_DOCKER_CONFIG=krb5-docker.conf
KRB5_DOCKER_TARGET=http://kerberos-web.zap.test:8080
KRB5_HOST_CONFIG=krb5-host.conf
KRB5_HOST_TARGET=http://kerberos-web.zap.test:8602
ENVEOF

cat > /shared/TESTBED.txt <<'TXTEOF'
Kerberos testbed generated files
================================

Client principal:  zapuser@ZAP.TEST
Client password:   ZapTest123!
Client keytab:     zapuser.keytab

HTTP SPN:          HTTP/kerberos-web.zap.test@ZAP.TEST
Server keytab:     http.keytab

For a ZAP/container joined to Docker network "zap-auth-testbed":
  krb5 config:     krb5-docker.conf (same content as krb5.conf)
  target:          http://kerberos-web.zap.test:8080

For ZAP running directly on the Docker host:
  krb5 config:     krb5-host.conf
  KDC:             127.0.0.1:10088
  target:          http://kerberos-web.zap.test:8602
  /etc/hosts:      127.0.0.1 kerberos-web.zap.test

Never use http.keytab as a client keytab. It belongs to the test web server.
TXTEOF

chmod 644 /shared/zapuser.keytab /shared/http.keytab
chmod 644 /shared/krb5.conf /shared/krb5-docker.conf /shared/krb5-host.conf /shared/TESTBED.txt /shared/kerberos-client.env

# Human-readable inventory useful when debugging generated artifacts.
klist -kte /shared/zapuser.keytab > /shared/zapuser.keytab.txt
klist -kte /shared/http.keytab > /shared/http.keytab.txt
chmod 644 /shared/*.keytab.txt

echo '[kerberos-kdc] Generated /shared:'
ls -l /shared

exec krb5kdc -n
