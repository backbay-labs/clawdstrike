-- Add external_id column and enforce runtime uniqueness per endpoint.
--
-- Runtime nodes represent AI agent runtimes that register under an endpoint
-- (hushd daemon).  The same runtime (identified by external_id) must not
-- appear twice under the same parent endpoint within a tenant.

-- 1. Add the external_id column.
--    This is an optional, caller-supplied identifier (e.g. the agent runtime's
--    own UUID or slug) that is distinct from the auto-generated primary key.
--    Existing rows get NULL which is fine — the unique index below filters on
--    node_type = 'runtime' so NULLs in other node types are harmless.
ALTER TABLE hierarchy_nodes
    ADD COLUMN IF NOT EXISTS external_id TEXT;

-- 2. Partial unique index: within a tenant, no two runtime nodes under the
--    same parent may share an external_id.  This prevents duplicate runtime
--    registrations under an endpoint.
--
--    The WHERE clause limits the constraint to runtime nodes only; other node
--    types are unaffected.  NULLs in external_id are excluded by PostgreSQL's
--    unique-index semantics (NULL != NULL), so runtimes without an external_id
--    are still allowed.
CREATE UNIQUE INDEX IF NOT EXISTS idx_hierarchy_nodes_runtime_unique
    ON hierarchy_nodes (tenant_id, parent_id, external_id)
    WHERE node_type = 'runtime';

-- 3. Supporting index for fast lookups by external_id within a tenant.
CREATE INDEX IF NOT EXISTS idx_hierarchy_nodes_external_id
    ON hierarchy_nodes (tenant_id, external_id)
    WHERE external_id IS NOT NULL;
