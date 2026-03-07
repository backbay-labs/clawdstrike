CREATE TABLE IF NOT EXISTS hunt_envelopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    issuer TEXT,
    issued_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL,
    envelope_hash TEXT,
    schema_name TEXT,
    raw_ref TEXT NOT NULL,
    raw_envelope JSONB NOT NULL,
    signature_valid BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT hunt_envelopes_tenant_id_id_key UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, raw_ref)
);

CREATE TABLE IF NOT EXISTS hunt_events (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    envelope_id UUID,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL,
    verdict TEXT NOT NULL,
    severity TEXT,
    summary TEXT NOT NULL,
    action_type TEXT,
    process TEXT,
    namespace TEXT,
    pod TEXT,
    session_id TEXT,
    endpoint_agent_id TEXT,
    runtime_agent_id TEXT,
    principal_id TEXT,
    grant_id TEXT,
    response_action_id TEXT,
    detection_ids TEXT[] NOT NULL DEFAULT '{}',
    target_kind TEXT,
    target_id TEXT,
    target_name TEXT,
    envelope_hash TEXT,
    issuer TEXT,
    schema_name TEXT,
    signature_valid BOOLEAN,
    raw_ref TEXT NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT hunt_events_envelope_tenant_fk
        FOREIGN KEY (tenant_id, envelope_id)
        REFERENCES hunt_envelopes(tenant_id, id)
        ON DELETE SET NULL (envelope_id),
    PRIMARY KEY (tenant_id, event_id)
);

CREATE TABLE IF NOT EXISTS saved_hunts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    query JSONB NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS hunt_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    request JSONB NOT NULL,
    result JSONB,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hunt_envelopes_tenant_issued_at ON hunt_envelopes(tenant_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_events_tenant_time ON hunt_events(tenant_id, timestamp DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_events_tenant_source ON hunt_events(tenant_id, source, timestamp DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_events_tenant_principal ON hunt_events(tenant_id, principal_id, timestamp DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_events_tenant_session ON hunt_events(tenant_id, session_id, timestamp DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_events_tenant_endpoint ON hunt_events(tenant_id, endpoint_agent_id, timestamp DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_events_tenant_runtime ON hunt_events(tenant_id, runtime_agent_id, timestamp DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_events_detection_ids ON hunt_events USING GIN(detection_ids);
CREATE INDEX IF NOT EXISTS idx_saved_hunts_tenant_updated ON saved_hunts(tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_jobs_tenant_created ON hunt_jobs(tenant_id, created_at DESC);
