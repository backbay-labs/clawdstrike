//! SQLite schema for hushd control-plane state.

pub const CREATE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS control_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Sessions (identity-aware)
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    org_id TEXT,
    created_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    terminated_at TEXT,
    session_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_org_id ON sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- RBAC roles + assignments
CREATE TABLE IF NOT EXISTS rbac_roles (
    id TEXT PRIMARY KEY,
    role_json TEXT NOT NULL,
    builtin INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rbac_role_assignments (
    id TEXT PRIMARY KEY,
    principal_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    expires_at TEXT,
    reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_rbac_assignments_principal ON rbac_role_assignments(principal_type, principal_id);
CREATE INDEX IF NOT EXISTS idx_rbac_assignments_role ON rbac_role_assignments(role_id);

-- Approval requests (used when RBAC constraints require approval)
CREATE TABLE IF NOT EXISTS approval_requests (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approver_roles_json TEXT NOT NULL,
    required_approvals INTEGER NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_json TEXT
);

-- Scoped policies + assignments (identity-based policy resolution)
CREATE TABLE IF NOT EXISTS scoped_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    priority INTEGER NOT NULL,
    merge_strategy TEXT NOT NULL,
    policy_yaml TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    metadata_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scoped_policies_priority ON scoped_policies(priority);
CREATE INDEX IF NOT EXISTS idx_scoped_policies_enabled ON scoped_policies(enabled);

CREATE TABLE IF NOT EXISTS policy_assignments (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    priority INTEGER NOT NULL,
    effective_from TEXT,
    effective_until TEXT,
    assigned_by TEXT NOT NULL,
    assigned_at TEXT NOT NULL,
    reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_policy_assignments_target ON policy_assignments(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_policy_assignments_policy ON policy_assignments(policy_id);

-- OIDC replay protection (jti)
CREATE TABLE IF NOT EXISTS oidc_jti (
    issuer TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (issuer, jti)
);

CREATE INDEX IF NOT EXISTS idx_oidc_jti_expires_at ON oidc_jti(expires_at);

INSERT OR REPLACE INTO control_metadata (key, value) VALUES ('schema_version', '4');
"#;
