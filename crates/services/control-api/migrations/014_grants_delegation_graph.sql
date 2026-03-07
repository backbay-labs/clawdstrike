-- Durable delegation grant ledger and operator-queryable graph surfaces.

CREATE TABLE IF NOT EXISTS fleet_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issuer_principal_id TEXT NOT NULL,
    subject_principal_id TEXT NOT NULL,
    grant_type TEXT NOT NULL DEFAULT 'delegation'
        CHECK (grant_type IN ('delegation', 'approval', 'session_override')),
    audience TEXT NOT NULL,
    token_jti TEXT NOT NULL,
    parent_grant_id UUID,
    parent_token_jti TEXT,
    delegation_depth INTEGER NOT NULL DEFAULT 0,
    lineage_chain JSONB NOT NULL DEFAULT '[]'::jsonb,
    lineage_resolved BOOLEAN NOT NULL DEFAULT true,
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    capability_ceiling JSONB NOT NULL DEFAULT '[]'::jsonb,
    purpose TEXT,
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_approval_id TEXT,
    source_session_id TEXT,
    issued_at TIMESTAMPTZ NOT NULL,
    not_before TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'expired', 'revoked')),
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    revoke_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fleet_grants_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT fleet_grants_parent_tenant_fk
        FOREIGN KEY (tenant_id, parent_grant_id)
        REFERENCES fleet_grants(tenant_id, id)
        ON DELETE SET NULL (parent_grant_id),
    UNIQUE (tenant_id, token_jti)
);

CREATE INDEX IF NOT EXISTS idx_fleet_grants_tenant_issued
ON fleet_grants(tenant_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_fleet_grants_tenant_subject
ON fleet_grants(tenant_id, subject_principal_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_fleet_grants_tenant_issuer
ON fleet_grants(tenant_id, issuer_principal_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_fleet_grants_parent
ON fleet_grants(tenant_id, parent_grant_id);

CREATE INDEX IF NOT EXISTS idx_fleet_grants_parent_token
ON fleet_grants(tenant_id, parent_token_jti);

CREATE INDEX IF NOT EXISTS idx_fleet_grants_status
ON fleet_grants(tenant_id, status, expires_at DESC);

CREATE TABLE IF NOT EXISTS delegation_graph_nodes (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN (
        'principal',
        'session',
        'grant',
        'approval',
        'event',
        'response_action'
    )),
    label TEXT NOT NULL,
    state TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_delegation_graph_nodes_kind
ON delegation_graph_nodes(tenant_id, kind, updated_at DESC);

CREATE TABLE IF NOT EXISTS delegation_graph_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_node_id TEXT NOT NULL,
    to_node_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN (
        'issued_grant',
        'received_grant',
        'derived_from_grant',
        'spawned_principal',
        'approved_by',
        'revoked_by',
        'exercised_in_session',
        'exercised_in_event',
        'triggered_response_action'
    )),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, from_node_id, to_node_id, kind),
    FOREIGN KEY (tenant_id, from_node_id)
        REFERENCES delegation_graph_nodes(tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, to_node_id)
        REFERENCES delegation_graph_nodes(tenant_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_delegation_graph_edges_from
ON delegation_graph_edges(tenant_id, from_node_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_delegation_graph_edges_to
ON delegation_graph_edges(tenant_id, to_node_id, created_at DESC);
