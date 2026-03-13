-- Phase 2: Endpoint/Runtime two-level agent hierarchy.
--
-- Splits the previous "agent" node type into "endpoint" (hushd daemon) and
-- "runtime" (AI agent runtime).  Existing "agent" rows are migrated to
-- "endpoint".

-- 1. hierarchy_nodes: widen the CHECK constraint to include new types.
ALTER TABLE hierarchy_nodes
    DROP CONSTRAINT IF EXISTS hierarchy_nodes_node_type_check;

ALTER TABLE hierarchy_nodes
    ADD CONSTRAINT hierarchy_nodes_node_type_check
    CHECK (node_type IN ('org', 'team', 'project', 'agent', 'endpoint', 'runtime'));

-- Migrate existing "agent" rows to "endpoint".
UPDATE hierarchy_nodes
   SET node_type = 'endpoint',
       updated_at = now()
 WHERE node_type = 'agent';

-- Index for efficient type + parent queries (e.g. "all runtimes under this endpoint").
CREATE INDEX IF NOT EXISTS idx_hierarchy_nodes_type_parent
    ON hierarchy_nodes (tenant_id, node_type, parent_id);

-- 2. principal_memberships: widen target_kind to allow 'endpoint'.
ALTER TABLE principal_memberships
    DROP CONSTRAINT IF EXISTS principal_memberships_target_kind_check;

ALTER TABLE principal_memberships
    ADD CONSTRAINT principal_memberships_target_kind_check
    CHECK (target_kind IN ('swarm', 'project', 'capability_group', 'endpoint'));
