-- Fleet directory principal compatibility links.
-- Adds agents.principal_id and backfills endpoint/operator principals.

ALTER TABLE agents
ADD COLUMN IF NOT EXISTS principal_id UUID;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'agents_principal_id_fkey'
    ) THEN
        ALTER TABLE agents
            DROP CONSTRAINT agents_principal_id_fkey;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'agents_principal_tenant_fk'
    ) THEN
        ALTER TABLE agents
            ADD CONSTRAINT agents_principal_tenant_fk
            FOREIGN KEY (tenant_id, principal_id)
            REFERENCES principals(tenant_id, id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_agents_tenant_principal
ON agents(tenant_id, principal_id)
WHERE principal_id IS NOT NULL;

INSERT INTO principals (
    tenant_id,
    principal_type,
    stable_ref,
    display_name,
    trust_level,
    lifecycle_state,
    liveness_state,
    public_key,
    metadata
)
SELECT
    a.tenant_id,
    'endpoint_agent',
    a.agent_id,
    a.name,
    CASE
        WHEN a.trust_level IN ('untrusted', 'low', 'medium', 'high', 'system') THEN a.trust_level
        ELSE 'medium'
    END,
    CASE a.status
        WHEN 'inactive' THEN 'inactive'
        WHEN 'revoked' THEN 'revoked'
        ELSE 'active'
    END,
    CASE a.status
        WHEN 'stale' THEN 'stale'
        WHEN 'dead' THEN 'dead'
        WHEN 'inactive' THEN 'unknown'
        WHEN 'revoked' THEN 'unknown'
        ELSE 'active'
    END,
    a.public_key,
    COALESCE(a.metadata, '{}'::jsonb)
FROM agents AS a
ON CONFLICT (tenant_id, principal_type, stable_ref) DO UPDATE
SET display_name = EXCLUDED.display_name,
    trust_level = EXCLUDED.trust_level,
    lifecycle_state = EXCLUDED.lifecycle_state,
    liveness_state = EXCLUDED.liveness_state,
    public_key = EXCLUDED.public_key,
    metadata = EXCLUDED.metadata,
    updated_at = now();

INSERT INTO principals (
    tenant_id,
    principal_type,
    stable_ref,
    display_name,
    trust_level,
    lifecycle_state,
    liveness_state,
    metadata
)
SELECT
    u.tenant_id,
    'operator',
    u.id::text,
    u.name,
    CASE
        WHEN u.role IN ('owner', 'admin') THEN 'high'
        ELSE 'medium'
    END,
    'active',
    NULL,
    jsonb_build_object(
        'email', u.email,
        'role', u.role,
        'auth_provider', u.auth_provider,
        'auth_provider_id', u.auth_provider_id
    )
FROM users AS u
ON CONFLICT (tenant_id, principal_type, stable_ref) DO UPDATE
SET display_name = EXCLUDED.display_name,
    trust_level = EXCLUDED.trust_level,
    metadata = EXCLUDED.metadata,
    updated_at = now();

UPDATE agents AS a
SET principal_id = p.id
FROM principals AS p
WHERE p.tenant_id = a.tenant_id
  AND p.principal_type = 'endpoint_agent'
  AND p.stable_ref = a.agent_id
  AND a.principal_id IS NULL;
