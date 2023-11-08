#!/usr/bin/env bash

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN=root

set -exo pipefail

vault auth enable -path=imap vault-plugin-auth-imap

vault write auth/imap/config imap_server=$MAILSERVER

vault read auth/imap/config

vault write auth/imap/role/testing token_policies=default

vault read auth/imap/role/testing

echo "vault write auth/imap/login role=testing username=\$MAILADDRESS password=\$MAILPASSWORD"
