-- Tenant-level active policy state used for converge-on-enroll/recovery flows.

CREATE TABLE IF NOT EXISTS tenant_active_policies (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    policy_yaml TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    description TEXT,
    version BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tenant_active_policies_updated_at
ON tenant_active_policies(updated_at DESC);
