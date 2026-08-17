#!/bin/sh
set -eu
mkdir -p /shared /var/lib/krb5kdc /etc/krb5kdc
printf '*/admin@ZAP.TEST *\n' > /etc/krb5kdc/kadm5.acl
if [ ! -f /var/lib/krb5kdc/principal ]; then
  kdb5_util create -s -P 'MasterPass123!'
  kadmin.local -q "addprinc -pw ZapTest123! zapuser@ZAP.TEST"
  kadmin.local -q "addprinc -randkey HTTP/kerberos-web.zap.test@ZAP.TEST"
  kadmin.local -q "addprinc -randkey HTTP/kerberos-web.as-backend_default@ZAP.TEST"
  kadmin.local -q "addprinc -randkey HTTP/kerberos-web.zap-auth-testbed@ZAP.TEST"
  rm -f /shared/http.keytab /shared/zapuser.keytab
fi
if [ ! -s /shared/http.keytab ]; then
  kadmin.local -q \
    "ktadd -norandkey -k /shared/http.keytab HTTP/kerberos-web.zap.test@ZAP.TEST"
  kadmin.local -q \
    "ktadd -norandkey -k /shared/http.keytab HTTP/kerberos-web.as-backend_default@ZAP.TEST"
  kadmin.local -q \
    "ktadd -norandkey -k /shared/http.keytab HTTP/kerberos-web.zap-auth-testbed@ZAP.TEST"
fi
if [ ! -s /shared/zapuser.keytab ]; then
  kadmin.local -q "ktadd -norandkey -k /shared/zapuser.keytab zapuser@ZAP.TEST"
fi
cp /etc/krb5.conf /shared/krb5.conf
chmod 644 /shared/http.keytab /shared/zapuser.keytab /shared/krb5.conf
exec krb5kdc -n
