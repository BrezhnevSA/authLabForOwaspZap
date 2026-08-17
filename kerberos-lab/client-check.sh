#!/bin/sh
set -eu
printf '%s\n' 'ZapTest123!' | kinit zapuser@ZAP.TEST
curl --fail --silent --show-error --negotiate -u : http://kerberos-web.zap.test:8080/api/whoami
printf '\n'
