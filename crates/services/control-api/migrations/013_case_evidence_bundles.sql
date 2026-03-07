CREATE TABLE IF NOT EXISTS fleet_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    summary TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL CHECK (status IN ('open', 'in_progress', 'contained', 'closed')),
    created_by TEXT NOT NULL,
    principal_ids TEXT[] NOT NULL DEFAULT '{}',
    detection_ids TEXT[] NOT NULL DEFAULT '{}',
    response_action_ids TEXT[] NOT NULL DEFAULT '{}',
    grant_ids TEXT[] NOT NULL DEFAULT '{}',
    tags TEXT[] NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fleet_cases_tenant_id_id_key UNIQUE (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_fleet_cases_tenant_updated
    ON fleet_cases(tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_fleet_cases_tenant_status
    ON fleet_cases(tenant_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS fleet_case_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id UUID NOT NULL,
    artifact_kind TEXT NOT NULL CHECK (
        artifact_kind IN (
            'fleet_event',
            'raw_envelope',
            'saved_hunt',
            'hunt_job',
            'detection',
            'response_action',
            'grant',
            'graph_snapshot',
            'note',
            'bundle_export'
        )
    ),
    artifact_id TEXT NOT NULL,
    summary TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    added_by TEXT NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fleet_case_artifacts_case_tenant_fk
        FOREIGN KEY (tenant_id, case_id)
        REFERENCES fleet_cases(tenant_id, id)
        ON DELETE CASCADE,
    UNIQUE (case_id, artifact_kind, artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_fleet_case_artifacts_case_added
    ON fleet_case_artifacts(case_id, added_at DESC);
CREATE INDEX IF NOT EXISTS idx_fleet_case_artifacts_tenant_kind
    ON fleet_case_artifacts(tenant_id, artifact_kind, added_at DESC);

CREATE TABLE IF NOT EXISTS fleet_case_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id UUID NOT NULL,
    event_kind TEXT NOT NULL CHECK (
        event_kind IN (
            'case_created',
            'case_updated',
            'status_changed',
            'artifact_added',
            'bundle_requested',
            'bundle_completed',
            'bundle_failed'
        )
    ),
    actor_id TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fleet_case_events_case_tenant_fk
        FOREIGN KEY (tenant_id, case_id)
        REFERENCES fleet_cases(tenant_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_fleet_case_events_case_created
    ON fleet_case_events(case_id, created_at ASC);

CREATE TABLE IF NOT EXISTS fleet_evidence_bundles (
    export_id TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id UUID,
    status TEXT NOT NULL CHECK (status IN ('processing', 'completed', 'failed', 'expired')),
    requested_by TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    file_path TEXT,
    sha256 TEXT,
    size_bytes BIGINT,
    manifest_ref TEXT,
    expires_at TIMESTAMPTZ,
    retention_days INTEGER NOT NULL,
    filters JSONB NOT NULL DEFAULT '{}'::jsonb,
    artifact_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT fleet_evidence_bundles_case_tenant_fk
        FOREIGN KEY (tenant_id, case_id)
        REFERENCES fleet_cases(tenant_id, id)
        ON DELETE SET NULL (case_id)
);

CREATE INDEX IF NOT EXISTS idx_fleet_evidence_bundles_case_requested
    ON fleet_evidence_bundles(case_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_fleet_evidence_bundles_tenant_status
    ON fleet_evidence_bundles(tenant_id, status, requested_at DESC);
