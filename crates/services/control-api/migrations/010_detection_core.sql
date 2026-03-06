CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    source_format TEXT NOT NULL CHECK (
        source_format IN (
            'native_correlation',
            'sigma',
            'yara',
            'clawdstrike_policy',
            'threshold'
        )
    ),
    engine_kind TEXT NOT NULL CHECK (
        engine_kind IN ('correlation', 'content', 'policy_guard', 'threshold')
    ),
    execution_mode TEXT NOT NULL CHECK (
        execution_mode IN ('streaming', 'batch', 'inline', 'scheduled')
    ),
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    mitre_attack JSONB NOT NULL DEFAULT '[]'::jsonb,
    author TEXT,
    source_text TEXT,
    source_object JSONB,
    compiled_artifact JSONB,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS detection_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL,
    rule_name TEXT NOT NULL,
    source_format TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL CHECK (
        status IN ('open', 'suppressed', 'resolved', 'false_positive', 'expired')
    ),
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    principal_id UUID,
    session_id TEXT,
    grant_id UUID,
    response_action_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT detection_findings_rule_tenant_fk
        FOREIGN KEY (tenant_id, rule_id)
        REFERENCES detection_rules(tenant_id, id)
        ON DELETE CASCADE,
    UNIQUE (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS detection_finding_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    artifact_kind TEXT NOT NULL,
    artifact_ref TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT detection_finding_evidence_tenant_fk
        FOREIGN KEY (tenant_id, finding_id)
        REFERENCES detection_findings(tenant_id, id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS detection_suppressions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id UUID,
    finding_id UUID,
    scope JSONB NOT NULL DEFAULT '{}'::jsonb,
    match_criteria JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked')),
    CONSTRAINT detection_suppressions_rule_tenant_fk
        FOREIGN KEY (tenant_id, rule_id)
        REFERENCES detection_rules(tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT detection_suppressions_finding_tenant_fk
        FOREIGN KEY (tenant_id, finding_id)
        REFERENCES detection_findings(tenant_id, id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS installed_detection_packs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    package_type TEXT NOT NULL DEFAULT 'policy-pack' CHECK (package_type = 'policy-pack'),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    trust_level TEXT NOT NULL CHECK (
        trust_level IN ('unverified', 'signed', 'verified', 'certified')
    ),
    installed_by TEXT NOT NULL,
    installed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    UNIQUE (tenant_id, package_name, version)
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_tenant_enabled
    ON detection_rules(tenant_id, enabled, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_detection_findings_tenant_status
    ON detection_findings(tenant_id, status, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_detection_findings_tenant_rule
    ON detection_findings(tenant_id, rule_id, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_detection_findings_tenant_principal
    ON detection_findings(tenant_id, principal_id, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_detection_suppressions_tenant_status
    ON detection_suppressions(tenant_id, status, created_at DESC);
