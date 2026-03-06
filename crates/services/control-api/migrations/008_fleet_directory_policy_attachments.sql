-- Fleet directory policy attachments.
-- Adds attachment storage for tenant, swarm, project, capability-group, and principal policy layers.

CREATE TABLE IF NOT EXISTS policy_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL CHECK (
        target_kind IN ('tenant', 'swarm', 'project', 'capability_group', 'principal')
    ),
    target_id UUID,
    priority INTEGER NOT NULL DEFAULT 100,
    policy_ref TEXT,
    policy_yaml TEXT,
    checksum_sha256 TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT policy_attachments_target_scope_check CHECK (
        (target_kind = 'tenant' AND target_id IS NULL)
        OR (target_kind <> 'tenant' AND target_id IS NOT NULL)
    ),
    CONSTRAINT policy_attachments_payload_check CHECK (
        policy_ref IS NOT NULL OR policy_yaml IS NOT NULL
    )
);

CREATE INDEX IF NOT EXISTS idx_policy_attachments_lookup
ON policy_attachments(tenant_id, target_kind, priority, created_at, id);

CREATE INDEX IF NOT EXISTS idx_policy_attachments_target
ON policy_attachments(tenant_id, target_kind, target_id, priority, created_at, id);
