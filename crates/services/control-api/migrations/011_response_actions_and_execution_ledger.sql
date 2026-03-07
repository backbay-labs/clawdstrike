-- Durable fleet response-action ledger and acknowledgement scaffolding.
-- Depends on:
--   * 009_fleet_directory_references.sql for approvals(tenant_id, id)
--   * 010_detection_core.sql for detection_findings(tenant_id, id)
-- The fleet_cases tenant-scoped FK is added later in 015_response_action_case_links.sql
-- because fleet_cases is introduced in 013_case_evidence_bundles.sql.

CREATE TABLE IF NOT EXISTS response_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL CHECK (
        action_type IN (
            'transition_posture',
            'request_policy_reload',
            'terminate_session',
            'kill_switch',
            'quarantine_principal',
            'revoke_grant',
            'revoke_principal'
        )
    ),
    target_kind TEXT NOT NULL CHECK (
        target_kind IN (
            'endpoint',
            'runtime',
            'session',
            'principal',
            'grant',
            'swarm',
            'project'
        )
    ),
    target_id TEXT NOT NULL,
    requested_by_type TEXT NOT NULL CHECK (requested_by_type IN ('user', 'service')),
    requested_by_id TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    reason TEXT NOT NULL,
    case_id UUID,
    source_detection_id UUID,
    source_approval_id UUID,
    require_acknowledgement BOOLEAN NOT NULL DEFAULT true,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (
        status IN (
            'queued',
            'approved',
            'published',
            'acknowledged',
            'rejected',
            'failed',
            'expired',
            'cancelled'
        )
    ),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT response_actions_source_detection_tenant_fk
        FOREIGN KEY (tenant_id, source_detection_id)
        REFERENCES detection_findings(tenant_id, id),
    CONSTRAINT response_actions_source_approval_tenant_fk
        FOREIGN KEY (tenant_id, source_approval_id)
        REFERENCES approvals(tenant_id, id),
    CONSTRAINT response_actions_tenant_id_id_key
        UNIQUE (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_response_actions_tenant_requested
ON response_actions(tenant_id, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_response_actions_tenant_status
ON response_actions(tenant_id, status, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_response_actions_target
ON response_actions(tenant_id, target_kind, target_id);

CREATE TABLE IF NOT EXISTS response_action_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    executor_kind TEXT NOT NULL DEFAULT 'endpoint_agent' CHECK (
        executor_kind IN ('endpoint_agent', 'runtime_agent', 'session_api', 'cloud_only')
    ),
    delivery_subject TEXT,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (
        status IN (
            'queued',
            'approved',
            'published',
            'acknowledged',
            'rejected',
            'failed',
            'expired',
            'cancelled'
        )
    ),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    published_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    acknowledgement_deadline TIMESTAMPTZ,
    last_error TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT response_action_deliveries_action_tenant_fk
        FOREIGN KEY (tenant_id, action_id)
        REFERENCES response_actions(tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT response_action_deliveries_tenant_id_action_target_key
        UNIQUE (tenant_id, id, action_id, target_kind, target_id),
    UNIQUE (action_id, target_kind, target_id)
);

CREATE INDEX IF NOT EXISTS idx_response_action_deliveries_action
ON response_action_deliveries(action_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_response_action_deliveries_tenant_status
ON response_action_deliveries(tenant_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS response_action_acks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delivery_id UUID NOT NULL,
    action_id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('acknowledged', 'rejected', 'failed', 'expired')
    ),
    message TEXT,
    resulting_state TEXT,
    raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (delivery_id),
    CONSTRAINT response_action_acks_action_tenant_fk
        FOREIGN KEY (tenant_id, action_id)
        REFERENCES response_actions(tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT fk_response_action_acks_delivery
        FOREIGN KEY (tenant_id, delivery_id, action_id, target_kind, target_id)
        REFERENCES response_action_deliveries(tenant_id, id, action_id, target_kind, target_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_response_action_acks_action
ON response_action_acks(action_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_response_action_acks_tenant_target
ON response_action_acks(tenant_id, target_kind, target_id, observed_at DESC);
