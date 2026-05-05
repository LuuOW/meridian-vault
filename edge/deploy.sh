#!/usr/bin/env bash
# Deploy the meridian-vault Worker.
#
# Requires env vars (export them or source from /etc/meridian-vault/env):
#   CF_EMAIL CF_KEY CF_ACCOUNT VAULT_TOKEN VAULT_PASSPHRASE
#
# KV namespace `meridian-vault` (id 7a2a5118…) must already exist; one-shot
# created via the CF API.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

: "${CF_EMAIL:?need CF_EMAIL}"
: "${CF_KEY:?need CF_KEY}"
: "${CF_ACCOUNT:?need CF_ACCOUNT}"
: "${VAULT_TOKEN:?need VAULT_TOKEN}"
: "${VAULT_PASSPHRASE:?need VAULT_PASSPHRASE}"
KV_ID="${KV_ID:-7a2a5118cb8a4f03a261b61272e95a37}"

python3 "$HERE/build.py"

METADATA=$(cat <<JSON
{
  "main_module": "vault.mjs",
  "compatibility_date": "2025-01-01",
  "bindings": [
    { "type": "kv_namespace",  "name": "VAULT_KV",         "namespace_id": "$KV_ID" },
    { "type": "secret_text",   "name": "VAULT_TOKEN",      "text": "$VAULT_TOKEN" },
    { "type": "secret_text",   "name": "VAULT_PASSPHRASE", "text": "$VAULT_PASSPHRASE" }
  ]
}
JSON
)

curl -fsS -X PUT \
  -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" \
  -F "metadata=$METADATA;type=application/json" \
  -F "vault.mjs=@/tmp/vault.built.mjs;type=application/javascript+module;filename=vault.mjs" \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/workers/scripts/meridian-vault-proxy" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('deploy:', d.get('success')); err=d.get('errors'); err and print(json.dumps(err, indent=2))"
