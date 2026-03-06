-- Fleet directory principal joins for existing fleet workflows.
-- Adds approvals.principal_id and backfills endpoint-principal references.

ALTER TABLE approvals
ADD COLUMN IF NOT EXISTS principal_id UUID REFERENCES principals(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_approvals_tenant_principal
ON approvals(tenant_id, principal_id, created_at DESC)
WHERE principal_id IS NOT NULL;

UPDATE approvals AS ap
SET principal_id = p.id
FROM principals AS p
WHERE p.tenant_id = ap.tenant_id
  AND p.principal_type = 'endpoint_agent'
  AND p.stable_ref = ap.agent_id
  AND ap.principal_id IS NULL;
