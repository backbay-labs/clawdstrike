-- Hierarchy nodes: org/team/project/agent tree for policy inheritance.

CREATE TABLE IF NOT EXISTS hierarchy_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    node_type TEXT NOT NULL CHECK (node_type IN ('org', 'team', 'project', 'agent')),
    parent_id UUID REFERENCES hierarchy_nodes(id) ON DELETE SET NULL,
    policy_id UUID,
    policy_name TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Each tenant may have at most one root org node (parent_id IS NULL per type 'org').
CREATE UNIQUE INDEX IF NOT EXISTS uq_hierarchy_root_per_tenant
    ON hierarchy_nodes (tenant_id)
    WHERE parent_id IS NULL AND node_type = 'org';

-- Fast lookups by tenant + parent for tree construction.
CREATE INDEX IF NOT EXISTS idx_hierarchy_nodes_tenant_parent
    ON hierarchy_nodes (tenant_id, parent_id);

-- Fast lookups by tenant for listing all nodes.
CREATE INDEX IF NOT EXISTS idx_hierarchy_nodes_tenant
    ON hierarchy_nodes (tenant_id);
