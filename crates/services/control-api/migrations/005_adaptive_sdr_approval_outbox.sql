-- Durable cloud-side outbox for approval resolution publish retries.

CREATE TABLE IF NOT EXISTS approval_resolution_outbox (
    id BIGSERIAL PRIMARY KEY,
    approval_id UUID NOT NULL UNIQUE REFERENCES approvals(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tenant_slug TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_approval_resolution_outbox_pending
ON approval_resolution_outbox(status, next_attempt_at);

CREATE INDEX IF NOT EXISTS idx_approval_resolution_outbox_tenant
ON approval_resolution_outbox(tenant_id, created_at DESC);
