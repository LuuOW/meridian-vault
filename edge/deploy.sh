#!/usr/bin/env bash
# Deploy the meridian-vault Worker.
#
# Code-only deploy: the script body is replaced, the KV binding is set, and
# existing secret_text bindings (VAULT_TOKEN, VAULT_PASSPHRASE) are preserved
# via Cloudflare's `keep_bindings` directive. The deployer therefore does
# *not* need access to those secret values — they only need to be set once
# (via the CF dashboard or `wrangler secret put`).
#
# Required env vars: CF_EMAIL CF_KEY CF_ACCOUNT
# Optional:          KV_ID (defaults to the production namespace)
#
# To rotate VAULT_TOKEN / VAULT_PASSPHRASE, set them in CF separately, then
# redeploy — keep_bindings will keep whatever's currently set.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

: "${CF_EMAIL:?need CF_EMAIL}"
: "${CF_KEY:?need CF_KEY}"
: "${CF_ACCOUNT:?need CF_ACCOUNT}"
KV_ID="${KV_ID:-7a2a5118cb8a4f03a261b61272e95a37}"

python3 "$HERE/build.py"

METADATA=$(cat <<JSON
{
  "main_module": "vault.mjs",
  "compatibility_date": "2025-01-01",
  "bindings": [
    { "type": "kv_namespace", "name": "VAULT_KV", "namespace_id": "$KV_ID" }
  ],
  "keep_bindings": ["secret_text"]
}
JSON
)

curl -fsS -X PUT \
  -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" \
  -F "metadata=$METADATA;type=application/json" \
  -F "vault.mjs=@/tmp/vault.built.mjs;type=application/javascript+module;filename=vault.mjs" \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/workers/scripts/meridian-vault-proxy" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('deploy:', d.get('success')); err=d.get('errors'); err and print(json.dumps(err, indent=2))"
