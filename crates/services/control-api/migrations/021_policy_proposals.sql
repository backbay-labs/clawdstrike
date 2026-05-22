-- Durable policy proposal review path.
-- Stores policy-author submissions separately from tenant_active_policies so
-- non-admin authors can request review without mutating fleet policy state.

CREATE TABLE IF NOT EXISTS policy_proposals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_yaml TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'rejected', 'deployed')
    ),
    base_active_policy_version BIGINT NOT NULL DEFAULT 0,
    proposed_policy_version BIGINT NOT NULL,
    preview JSONB NOT NULL DEFAULT '{}'::jsonb,
    required_approvals INTEGER NOT NULL DEFAULT 2,
    approved_by TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    approval_notes JSONB NOT NULL DEFAULT '{}'::jsonb,
    impact JSONB,
    impact_attached_by TEXT,
    impact_attached_at TIMESTAMPTZ,
    deployed_policy_version BIGINT,
    deployment_id UUID,
    submitted_by TEXT NOT NULL,
    reviewed_by TEXT,
    review_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at TIMESTAMPTZ,
    deployed_at TIMESTAMPTZ,
    CONSTRAINT policy_proposals_version_check CHECK (
        proposed_policy_version > base_active_policy_version
    ),
    CONSTRAINT policy_proposals_approval_threshold_check CHECK (
        required_approvals >= 2
    ),
    CONSTRAINT policy_proposals_approved_by_check CHECK (
        cardinality(approved_by) <= required_approvals
    ),
    CONSTRAINT policy_proposals_deployed_approvals_check CHECK (
        status <> 'deployed' OR cardinality(approved_by) >= required_approvals
    ),
    CONSTRAINT policy_proposals_impact_check CHECK (
        (impact IS NULL AND impact_attached_by IS NULL AND impact_attached_at IS NULL)
        OR (impact IS NOT NULL AND impact_attached_by IS NOT NULL AND impact_attached_at IS NOT NULL)
    ),
    CONSTRAINT policy_proposals_terminal_review_check CHECK (
        (status = 'pending' AND reviewed_at IS NULL AND reviewed_by IS NULL)
        OR (status <> 'pending' AND reviewed_at IS NOT NULL AND reviewed_by IS NOT NULL)
    ),
    CONSTRAINT policy_proposals_deploy_check CHECK (
        (status = 'deployed' AND deployed_at IS NOT NULL AND deployed_policy_version IS NOT NULL AND deployment_id IS NOT NULL)
        OR (status <> 'deployed' AND deployed_at IS NULL AND deployed_policy_version IS NULL AND deployment_id IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_policy_proposals_tenant_status_created
ON policy_proposals(tenant_id, status, created_at DESC, id);

CREATE INDEX IF NOT EXISTS idx_policy_proposals_tenant_created
ON policy_proposals(tenant_id, created_at DESC, id);
