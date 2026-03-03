-- Adaptive SDR schema updates:
-- - Enrollment token lifecycle on tenants
-- - Stale/dead status support on agents
-- - Cloud-side approvals table

ALTER TABLE tenants
ADD COLUMN IF NOT EXISTS enrollment_token TEXT;

CREATE INDEX IF NOT EXISTS idx_tenants_enrollment_token
ON tenants(enrollment_token);

-- Expand agent status values to include stale/dead lifecycle states.
ALTER TABLE agents
DROP CONSTRAINT IF EXISTS agents_status_check;

ALTER TABLE agents
ADD CONSTRAINT agents_status_check
CHECK (status IN ('active', 'inactive', 'revoked', 'stale', 'dead'));

CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    resolved_by TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_approvals_tenant_status_created
ON approvals(tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_approvals_agent_id
ON approvals(agent_id);
