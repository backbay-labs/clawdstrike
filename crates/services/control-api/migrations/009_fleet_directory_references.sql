-- Fleet directory principal joins for existing fleet workflows.
-- Adds approvals.principal_id and backfills endpoint-principal references.

ALTER TABLE approvals
ADD COLUMN IF NOT EXISTS principal_id UUID;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'approvals_tenant_id_id_key'
    ) THEN
        ALTER TABLE approvals
            ADD CONSTRAINT approvals_tenant_id_id_key
            UNIQUE (tenant_id, id);
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'approvals_principal_id_fkey'
    ) THEN
        ALTER TABLE approvals
            DROP CONSTRAINT approvals_principal_id_fkey;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'approvals_principal_tenant_fk'
    ) THEN
        ALTER TABLE approvals
            ADD CONSTRAINT approvals_principal_tenant_fk
            FOREIGN KEY (tenant_id, principal_id)
            REFERENCES principals(tenant_id, id);
    END IF;
END $$;

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
