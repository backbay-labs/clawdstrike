CREATE TABLE IF NOT EXISTS endpoint_evidence_archives (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    archive_id TEXT NOT NULL,
    raw_ref TEXT NOT NULL,
    archive_hash TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    endpoint_agent_id TEXT,
    event_id TEXT,
    content_hash TEXT,
    graph_slice_id TEXT,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    retention_days INTEGER NOT NULL CHECK (retention_days >= 1),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    archive JSONB NOT NULL,
    verification JSONB NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, archive_id),
    UNIQUE (tenant_id, raw_ref),
    UNIQUE (tenant_id, archive_hash)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_evidence_archives_tenant_uploaded
    ON endpoint_evidence_archives(tenant_id, uploaded_at DESC, archive_id DESC);
CREATE INDEX IF NOT EXISTS idx_endpoint_evidence_archives_tenant_bundle
    ON endpoint_evidence_archives(tenant_id, bundle_id, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_endpoint_evidence_archives_tenant_endpoint
    ON endpoint_evidence_archives(tenant_id, endpoint_agent_id, uploaded_at DESC)
    WHERE endpoint_agent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_endpoint_evidence_archives_tenant_expires
    ON endpoint_evidence_archives(tenant_id, expires_at ASC);
