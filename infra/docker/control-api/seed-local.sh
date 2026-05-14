#!/bin/sh
set -eu

tenant_id="${CONTROL_API_BOOTSTRAP_TENANT_ID:-11111111-1111-4111-8111-111111111111}"
tenant_name="${CONTROL_API_BOOTSTRAP_TENANT_NAME:-ClawdStrike Local Dev}"
tenant_slug="${CONTROL_API_BOOTSTRAP_TENANT_SLUG:-localdev}"
api_key_name="${CONTROL_API_BOOTSTRAP_API_KEY_NAME:-local-admin}"
api_key="${CONTROL_API_BOOTSTRAP_API_KEY:-cs_local_dev_key}"
key_prefix="${CONTROL_API_BOOTSTRAP_KEY_PREFIX:-cs_local}"

database_url="postgresql://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${PGDATABASE}"
tenant_slug_sql=$(printf "%s" "$tenant_slug" | sed "s/'/''/g")

echo "[control-api-seed] waiting for migrated schema..."
until psql "$database_url" -Atqc \
  "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'api_keys'" \
  | grep -q '^1$'; do
  sleep 1
done

existing_tenant_id="$(
  psql "$database_url" -v ON_ERROR_STOP=1 -Atqc \
    "SELECT id FROM tenants WHERE slug = '${tenant_slug_sql}' LIMIT 1"
)"

if [ -n "$existing_tenant_id" ]; then
  tenant_id="$existing_tenant_id"
fi

key_hash="$(printf '%s' "$api_key" | sha256sum | awk '{print $1}')"

psql "$database_url" \
  -v ON_ERROR_STOP=1 \
  -v tenant_id="$tenant_id" \
  -v tenant_name="$tenant_name" \
  -v tenant_slug="$tenant_slug" \
  -v api_key_name="$api_key_name" \
  -v key_hash="$key_hash" \
  -v key_prefix="$key_prefix" <<'SQL'
INSERT INTO tenants (id, name, slug, plan, status, agent_limit, retention_days)
VALUES (:'tenant_id'::uuid, :'tenant_name', :'tenant_slug', 'enterprise', 'active', 100, 30)
ON CONFLICT (slug) DO UPDATE
SET name = EXCLUDED.name,
    plan = EXCLUDED.plan,
    status = EXCLUDED.status,
    agent_limit = EXCLUDED.agent_limit,
    retention_days = EXCLUDED.retention_days;

DELETE FROM api_keys
WHERE tenant_id = :'tenant_id'::uuid
  AND key_prefix = :'key_prefix';

INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, scopes)
VALUES (:'tenant_id'::uuid, :'api_key_name', :'key_hash', :'key_prefix', ARRAY['admin']);
SQL

echo "[control-api-seed] seeded tenant slug '${tenant_slug}' with local admin API key metadata"
