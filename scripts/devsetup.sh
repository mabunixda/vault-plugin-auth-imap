#!/usr/bin/env bash

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN=root

set -exo pipefail

if [ -z "$MAILSERVER" ]; then
    echo "MAILSERVER not set"
    exit 1
fi

vault auth enable -path=imap imap

vault write auth/imap/config imap_server=$MAILSERVER token_period=1h token_max_ttl=24h

vault read auth/imap/config

if [ -n "$DOMAIN" ]; then
    vault write auth/imap/role/testing principals="ˆ*.@${DOMAIN}$"
    vault write auth/imap/role/testing token_policies=default token_max_ttl=12h token_ttl=1h
    vault read auth/imap/role/testing
fi

echo "vault write auth/imap/login role=testing username=\$MAILADDRESS password=\$MAILPASSWORD"
