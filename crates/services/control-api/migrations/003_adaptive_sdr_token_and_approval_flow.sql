-- Adaptive SDR lifecycle hardening:
-- - Replace legacy tenants.enrollment_token with expiring one-time token rows.
-- - Add approval.request_id for end-to-end cloud/agent correlation.

CREATE TABLE IF NOT EXISTS tenant_enrollment_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_tenant_expires
ON tenant_enrollment_tokens(tenant_id, expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_unconsumed
ON tenant_enrollment_tokens(expires_at)
WHERE consumed_at IS NULL;

-- Hard cutover: remove the legacy non-expiring token column.
DROP INDEX IF EXISTS idx_tenants_enrollment_token;
ALTER TABLE tenants
DROP COLUMN IF EXISTS enrollment_token;

ALTER TABLE approvals
ADD COLUMN IF NOT EXISTS request_id TEXT;

UPDATE approvals
SET request_id = COALESCE(request_id, id::text)
WHERE request_id IS NULL;

ALTER TABLE approvals
ALTER COLUMN request_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_approvals_tenant_request_id
ON approvals(tenant_id, request_id);
