#!/bin/sh
set -eu
DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/kerberos-generated"

if [ ! -s "$DIR/zapuser.keytab" ] || [ ! -s "$DIR/krb5-docker.conf" ] || [ ! -s "$DIR/krb5-host.conf" ]; then
  echo "Kerberos client files have not been generated yet."
  echo "Run: docker compose --profile kerberos up --build -d"
  exit 1
fi

cat <<TXT
Kerberos client inputs for ZAP
==============================
Principal: zapuser@ZAP.TEST
Password:  ZapTest123!
Client keytab:
  $DIR/zapuser.keytab

ZAP/backend in Docker:
  config: $DIR/krb5-docker.conf
  target: http://kerberos-web.zap.test:8080

ZAP/backend on host:
  config: $DIR/krb5-host.conf
  target: http://kerberos-web.zap.test:8602
  hosts:  127.0.0.1 kerberos-web.zap.test
TXT
