-- Fleet directory core schema.
-- Adds tenant-scoped topology, identity, delegation, and membership tables.

CREATE TABLE IF NOT EXISTS swarms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('fleet', 'cluster', 'department', 'mission', 'custom')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT swarms_tenant_id_id_key UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_swarms_tenant_created
ON swarms(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    swarm_id UUID,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    environment TEXT CHECK (environment IN ('dev', 'staging', 'prod', 'custom')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT projects_tenant_swarm_fk
        FOREIGN KEY (tenant_id, swarm_id)
        REFERENCES swarms(tenant_id, id)
        ON DELETE SET NULL (swarm_id),
    UNIQUE (tenant_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_projects_tenant_created
ON projects(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_projects_swarm
ON projects(swarm_id)
WHERE swarm_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS capability_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_capability_groups_tenant_created
ON capability_groups(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS principals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_type TEXT NOT NULL CHECK (
        principal_type IN (
            'endpoint_agent',
            'runtime_agent',
            'delegated_agent',
            'operator',
            'service_account'
        )
    ),
    stable_ref TEXT NOT NULL,
    display_name TEXT NOT NULL,
    trust_level TEXT NOT NULL DEFAULT 'medium' CHECK (
        trust_level IN ('untrusted', 'low', 'medium', 'high', 'system')
    ),
    lifecycle_state TEXT NOT NULL DEFAULT 'active' CHECK (
        lifecycle_state IN (
            'active',
            'inactive',
            'restricted',
            'observe_only',
            'quarantined',
            'revoked'
        )
    ),
    liveness_state TEXT CHECK (liveness_state IN ('unknown', 'active', 'stale', 'dead')),
    public_key TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT principals_tenant_id_id_key UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, principal_type, stable_ref)
);

CREATE INDEX IF NOT EXISTS idx_principals_tenant_type
ON principals(tenant_id, principal_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_principals_tenant_lifecycle
ON principals(tenant_id, lifecycle_state, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_principals_tenant_liveness
ON principals(tenant_id, liveness_state, created_at DESC)
WHERE liveness_state IS NOT NULL;

CREATE TABLE IF NOT EXISTS principal_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_id UUID NOT NULL,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('swarm', 'project', 'capability_group')),
    target_id UUID NOT NULL,
    role TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT principal_memberships_principal_tenant_fk
        FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals(tenant_id, id)
        ON DELETE CASCADE,
    UNIQUE (tenant_id, principal_id, target_kind, target_id)
);

CREATE INDEX IF NOT EXISTS idx_principal_memberships_principal
ON principal_memberships(tenant_id, principal_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_principal_memberships_target
ON principal_memberships(tenant_id, target_kind, target_id, created_at DESC);

-- approvals is created in 002_adaptive_sdr_schema.sql and remains the source table
-- for approval-linked delegation metadata in the directory model.
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
END $$;

CREATE TABLE IF NOT EXISTS grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issuer_principal_id UUID NOT NULL,
    subject_principal_id UUID NOT NULL,
    grant_type TEXT NOT NULL CHECK (grant_type IN ('delegation', 'approval', 'session_override')),
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked')),
    source_approval_id UUID,
    source_session_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT grants_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT grants_issuer_principal_tenant_fk
        FOREIGN KEY (tenant_id, issuer_principal_id)
        REFERENCES principals(tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT grants_subject_principal_tenant_fk
        FOREIGN KEY (tenant_id, subject_principal_id)
        REFERENCES principals(tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT grants_source_approval_tenant_fk
        FOREIGN KEY (tenant_id, source_approval_id)
        REFERENCES approvals(tenant_id, id)
        ON DELETE SET NULL (source_approval_id)
);

CREATE INDEX IF NOT EXISTS idx_grants_tenant_subject
ON grants(tenant_id, subject_principal_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_grants_tenant_status
ON grants(tenant_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS delegation_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    parent_principal_id UUID NOT NULL,
    child_principal_id UUID NOT NULL,
    grant_id UUID NOT NULL,
    token_id TEXT,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT delegation_edges_parent_principal_tenant_fk
        FOREIGN KEY (tenant_id, parent_principal_id)
        REFERENCES principals(tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT delegation_edges_child_principal_tenant_fk
        FOREIGN KEY (tenant_id, child_principal_id)
        REFERENCES principals(tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT delegation_edges_grant_tenant_fk
        FOREIGN KEY (tenant_id, grant_id)
        REFERENCES grants(tenant_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_delegation_edges_parent
ON delegation_edges(tenant_id, parent_principal_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_delegation_edges_child
ON delegation_edges(tenant_id, child_principal_id, issued_at DESC);
