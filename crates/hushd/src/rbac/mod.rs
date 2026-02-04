//! Role-based access control (RBAC) for hushd control-plane operations.
//!
//! This is intentionally scoped to "who can do what" in the daemon (policy/audit/session management),
//! not OS-level sandboxing.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use globset::{Glob, GlobMatcher};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::config::{GroupMappingConfig, RbacConfig};
use crate::control_db::ControlDb;

#[derive(Debug, thiserror::Error)]
pub enum RbacError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

pub type Result<T> = std::result::Result<T, RbacError>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    #[serde(rename = "*")]
    All,
    Policy,
    PolicyAssignment,
    Guard,
    Ruleset,
    AuditLog,
    Session,
    Exception,
    Tenant,
    User,
    Role,
}

impl ResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "*",
            Self::Policy => "policy",
            Self::PolicyAssignment => "policy_assignment",
            Self::Guard => "guard",
            Self::Ruleset => "ruleset",
            Self::AuditLog => "audit_log",
            Self::Session => "session",
            Self::Exception => "exception",
            Self::Tenant => "tenant",
            Self::User => "user",
            Self::Role => "role",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[serde(rename = "*")]
    All,
    Create,
    Read,
    Update,
    Delete,
    Assign,
    Unassign,
    Enable,
    Disable,
    Grant,
    Revoke,
    Export,
    Import,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "*",
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Assign => "assign",
            Self::Unassign => "unassign",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Grant => "grant",
            Self::Revoke => "revoke",
            Self::Export => "export",
            Self::Import => "import",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Permission {
    pub resource: ResourceType,
    pub actions: Vec<Action>,
    #[serde(default)]
    pub constraints: Vec<PermissionConstraint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PermissionConstraint {
    Scope(ScopeConstraint),
    Attribute(AttributeConstraint),
    Time(TimeConstraint),
    Approval(ApprovalConstraint),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeConstraint {
    pub scope_types: Vec<ScopeType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_values: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeType {
    Global,
    Organization,
    Team,
    Project,
    User,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttributeConstraint {
    pub attribute: String,
    pub operator: AttributeOperator,
    pub value: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeOperator {
    Eq,
    Ne,
    In,
    NotIn,
    Matches,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeConstraint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_hours: Option<HourRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_days: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HourRange {
    pub start: u8,
    pub end: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalConstraint {
    pub approver_roles: Vec<String>,
    pub required_approvals: u32,
    pub approval_ttl_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleScope {
    #[serde(rename = "type")]
    pub scope_type: ScopeType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub include_children: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: String,
    pub permissions: Vec<Permission>,
    #[serde(default)]
    pub inherits: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<RoleScope>,
    pub builtin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Principal {
    #[serde(rename = "type")]
    pub principal_type: PrincipalType,
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    User,
    ServiceAccount,
    Group,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub id: String,
    pub principal: Principal,
    pub role_id: String,
    pub scope: RoleScope,
    pub granted_by: String,
    pub granted_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionCheck {
    pub principal: Principal,
    pub resource: ResourceRef,
    pub action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<RoleScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceRef {
    #[serde(rename = "type")]
    pub resource_type: ResourceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    pub approver_roles: Vec<String>,
    pub required_approvals: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionResult {
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granting_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_constraints: Option<Vec<PermissionConstraint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_requirements: Option<ApprovalRequirement>,
}

#[derive(Clone, Debug)]
pub struct ApprovalRequest {
    pub id: String,
    pub created_at: String,
    pub expires_at: String,
    pub approver_roles: Vec<String>,
    pub required_approvals: u32,
    pub resource: ResourceType,
    pub action: Action,
    pub actor: Option<Principal>,
}

pub trait RbacStore: Send + Sync {
    fn get_role(&self, role_id: &str) -> Result<Option<Role>>;
    fn upsert_role(&self, role: &Role) -> Result<()>;
    fn list_roles(&self) -> Result<Vec<Role>>;

    fn insert_approval_request(&self, request: &ApprovalRequest) -> Result<()>;
}

#[derive(Clone)]
pub struct InMemoryRbacStore {
    inner: Arc<Mutex<InMemoryInner>>,
}

struct InMemoryInner {
    roles: HashMap<String, Role>,
    approval_requests: HashMap<String, ApprovalRequest>,
}

impl InMemoryRbacStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemoryInner {
                roles: HashMap::new(),
                approval_requests: HashMap::new(),
            })),
        }
    }
}

impl Default for InMemoryRbacStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RbacStore for InMemoryRbacStore {
    fn get_role(&self, role_id: &str) -> Result<Option<Role>> {
        Ok(self.inner.lock().unwrap_or_else(|e| e.into_inner()).roles.get(role_id).cloned())
    }

    fn upsert_role(&self, role: &Role) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .roles
            .insert(role.id.clone(), role.clone());
        Ok(())
    }

    fn list_roles(&self) -> Result<Vec<Role>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .roles
            .values()
            .cloned()
            .collect())
    }

    fn insert_approval_request(&self, request: &ApprovalRequest) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .approval_requests
            .insert(request.id.clone(), request.clone());
        Ok(())
    }
}

#[derive(Clone)]
pub struct SqliteRbacStore {
    db: Arc<ControlDb>,
}

impl SqliteRbacStore {
    pub fn new(db: Arc<ControlDb>) -> Self {
        Self { db }
    }
}

impl RbacStore for SqliteRbacStore {
    fn get_role(&self, role_id: &str) -> Result<Option<Role>> {
        let conn = self.db.lock_conn();
        let mut stmt = conn.prepare("SELECT role_json FROM rbac_roles WHERE id = ?1")?;
        let mut rows = stmt.query(rusqlite::params![role_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let role_json: String = row.get(0)?;
        let role: Role = serde_json::from_str(&role_json)?;
        Ok(Some(role))
    }

    fn upsert_role(&self, role: &Role) -> Result<()> {
        let conn = self.db.lock_conn();
        let role_json = serde_json::to_string(role)?;
        conn.execute(
            r#"
INSERT OR REPLACE INTO rbac_roles (id, role_json, builtin, created_at, updated_at)
VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            rusqlite::params![
                role.id,
                role_json,
                if role.builtin { 1 } else { 0 },
                role.created_at,
                role.updated_at
            ],
        )?;
        Ok(())
    }

    fn list_roles(&self) -> Result<Vec<Role>> {
        let conn = self.db.lock_conn();
        let mut stmt = conn.prepare("SELECT role_json FROM rbac_roles ORDER BY id ASC")?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let role_json: String = row.get(0)?;
            let role: Role = serde_json::from_str(&role_json)?;
            out.push(role);
        }
        Ok(out)
    }

    fn insert_approval_request(&self, request: &ApprovalRequest) -> Result<()> {
        let conn = self.db.lock_conn();
        let actor_json = request
            .actor
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let approver_roles_json = serde_json::to_string(&request.approver_roles)?;
        conn.execute(
            r#"
INSERT INTO approval_requests
    (id, created_at, expires_at, approver_roles_json, required_approvals, resource, action, actor_json)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            rusqlite::params![
                request.id,
                request.created_at,
                request.expires_at,
                approver_roles_json,
                request.required_approvals,
                request.resource.as_str(),
                request.action.as_str(),
                actor_json
            ],
        )?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct RbacManager {
    store: Arc<dyn RbacStore>,
    config: Arc<RbacConfig>,
    mapping: Arc<GroupMappingCompiled>,
}

#[derive(Default)]
struct GroupMappingCompiled {
    direct: HashMap<String, Vec<String>>,
    glob_patterns: Vec<(GlobMatcher, Vec<String>)>,
    regex_patterns: Vec<(Regex, Vec<String>)>,
    include_all_groups: bool,
    role_prefix: Option<String>,
    configured: bool,
}

impl RbacManager {
    pub fn new(store: Arc<dyn RbacStore>, config: Arc<RbacConfig>) -> Result<Self> {
        let mapping = compile_group_mapping(&config.group_mapping)?;
        Ok(Self {
            store,
            config,
            mapping: Arc::new(mapping),
        })
    }

    pub fn seed_builtin_roles(&self) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        for mut role in builtin_roles(now.clone()) {
            if self.store.get_role(&role.id)?.is_some() {
                continue;
            }
            role.created_at = now.clone();
            role.updated_at = now.clone();
            self.store.upsert_role(&role)?;
        }
        Ok(())
    }

    pub fn effective_roles_for_identity(&self, identity: &clawdstrike::IdentityPrincipal) -> Vec<String> {
        // If RBAC is disabled, treat identity roles as role IDs (legacy behavior).
        if !self.config.enabled {
            return dedupe_strings(identity.roles.clone());
        }

        let mut out: HashSet<String> = HashSet::new();

        // Baseline role for authenticated users (read-only policies).
        out.insert("policy-viewer".to_string());

        if !self.mapping.configured {
            out.extend(identity.roles.iter().cloned());
            return sort_strings(out);
        }

        let mut groups: Vec<String> = Vec::new();
        groups.extend(identity.roles.iter().cloned());
        groups.extend(identity.teams.iter().cloned());

        for group in &groups {
            if let Some(mapped) = self.mapping.direct.get(group) {
                out.extend(mapped.iter().cloned());
            }

            for (matcher, roles) in &self.mapping.glob_patterns {
                if matcher.is_match(group) {
                    out.extend(roles.iter().cloned());
                }
            }

            for (re, roles) in &self.mapping.regex_patterns {
                if re.is_match(group) {
                    out.extend(roles.iter().cloned());
                }
            }

            if self.mapping.include_all_groups {
                let role = match self.mapping.role_prefix.as_deref() {
                    Some(prefix) => format!("{prefix}{group}"),
                    None => group.clone(),
                };
                out.insert(role);
            }
        }

        sort_strings(out)
    }

    pub fn effective_permission_strings_for_roles(&self, roles: &[String]) -> Result<Vec<String>> {
        let role_closure = self.expand_role_inheritance(roles)?;
        let mut out: HashSet<String> = HashSet::new();

        for role in role_closure {
            for perm in role.permissions {
                for action in &perm.actions {
                    out.insert(format!("{}:{}", perm.resource.as_str(), action.as_str()));
                }
            }
        }

        Ok(sort_strings(out))
    }

    pub fn check_permission_for_identity(
        &self,
        identity: &clawdstrike::IdentityPrincipal,
        resource_type: ResourceType,
        action: Action,
    ) -> Result<PermissionResult> {
        self.check_permission_for_identity_with_context(
            identity,
            ResourceRef {
                resource_type,
                id: None,
                attributes: None,
            },
            action,
            None,
        )
    }

    pub fn check_permission_for_identity_with_context(
        &self,
        identity: &clawdstrike::IdentityPrincipal,
        resource: ResourceRef,
        action: Action,
        scope: Option<RoleScope>,
    ) -> Result<PermissionResult> {
        if !self.config.enabled {
            // When disabled, allow only if the identity's roles explicitly include policy-admin/super-admin.
            let is_admin = identity
                .roles
                .iter()
                .any(|r| r == "policy-admin" || r == "super-admin");
            if is_admin {
                return Ok(PermissionResult {
                    allowed: true,
                    reason: "rbac_disabled_admin_override".to_string(),
                    granting_role: Some("policy-admin".to_string()),
                    applied_constraints: None,
                    requires_approval: None,
                    approval_requirements: None,
                });
            }

            return Ok(PermissionResult {
                allowed: false,
                reason: "rbac_disabled".to_string(),
                granting_role: None,
                applied_constraints: None,
                requires_approval: None,
                approval_requirements: None,
            });
        }

        let roles = self.effective_roles_for_identity(identity);
        let role_closure = self.expand_role_inheritance(&roles)?;

        let now = Utc::now();

        for role in role_closure {
            for perm in &role.permissions {
                if !permission_matches(perm, &resource.resource_type, &action) {
                    continue;
                }

                let mut approval: Option<ApprovalConstraint> = None;
                let mut applied: Vec<PermissionConstraint> = Vec::new();

                // Evaluate constraints (fail closed on unsupported context).
                let mut ok = true;
                for c in &perm.constraints {
                    match c {
                        PermissionConstraint::Time(tc) => {
                            if !time_constraint_allows(tc, now) {
                                ok = false;
                                break;
                            }
                            applied.push(c.clone());
                        }
                        PermissionConstraint::Scope(sc) => {
                            if !scope_constraint_allows(sc, scope.as_ref()) {
                                ok = false;
                                break;
                            }
                            applied.push(c.clone());
                        }
                        PermissionConstraint::Attribute(ac) => {
                            if !attribute_constraint_allows(ac, resource.attributes.as_ref())? {
                                ok = false;
                                break;
                            }
                            applied.push(c.clone());
                        }
                        PermissionConstraint::Approval(ac) => {
                            approval = Some(ac.clone());
                            applied.push(c.clone());
                        }
                    }
                }

                if !ok {
                    continue;
                }

                if let Some(ac) = approval {
                    let request_id = uuid::Uuid::new_v4().to_string();
                    let created_at = now.to_rfc3339();
                    let expires_at = (now + chrono::Duration::seconds(ac.approval_ttl_secs as i64)).to_rfc3339();

                    self.store.insert_approval_request(&ApprovalRequest {
                        id: request_id.clone(),
                        created_at,
                        expires_at,
                        approver_roles: ac.approver_roles.clone(),
                        required_approvals: ac.required_approvals,
                        resource: resource.resource_type.clone(),
                        action: action.clone(),
                        actor: Some(Principal {
                            principal_type: PrincipalType::User,
                            id: identity.id.clone(),
                        }),
                    })?;

                    return Ok(PermissionResult {
                        allowed: false,
                        reason: "approval_required".to_string(),
                        granting_role: Some(role.id),
                        applied_constraints: Some(applied),
                        requires_approval: Some(true),
                        approval_requirements: Some(ApprovalRequirement {
                            approver_roles: ac.approver_roles,
                            required_approvals: ac.required_approvals,
                            request_id: Some(request_id),
                        }),
                    });
                }

                return Ok(PermissionResult {
                    allowed: true,
                    reason: "allowed".to_string(),
                    granting_role: Some(role.id),
                    applied_constraints: (!applied.is_empty()).then_some(applied),
                    requires_approval: None,
                    approval_requirements: None,
                });
            }
        }

        Ok(PermissionResult {
            allowed: false,
            reason: "denied".to_string(),
            granting_role: None,
            applied_constraints: None,
            requires_approval: None,
            approval_requirements: None,
        })
    }

    fn expand_role_inheritance(&self, roles: &[String]) -> Result<Vec<Role>> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = roles.to_vec();
        let mut out: Vec<Role> = Vec::new();

        while let Some(role_id) = stack.pop() {
            if !visited.insert(role_id.clone()) {
                continue;
            }

            let Some(role) = self.store.get_role(&role_id)? else {
                continue;
            };

            for parent in &role.inherits {
                stack.push(parent.clone());
            }

            out.push(role);
        }

        Ok(out)
    }
}

fn compile_group_mapping(cfg: &GroupMappingConfig) -> Result<GroupMappingCompiled> {
    let configured = !cfg.direct.is_empty() || !cfg.patterns.is_empty() || cfg.include_all_groups;

    let mut glob_patterns = Vec::new();
    let mut regex_patterns = Vec::new();

    for p in &cfg.patterns {
        if p.roles.is_empty() {
            continue;
        }

        if p.is_regex {
            let re = Regex::new(&p.pattern)
                .map_err(|e| RbacError::InvalidConfig(format!("invalid regex {}: {e}", p.pattern)))?;
            regex_patterns.push((re, p.roles.clone()));
        } else {
            let glob = Glob::new(&p.pattern).map_err(|e| {
                RbacError::InvalidConfig(format!("invalid glob {}: {e}", p.pattern))
            })?;
            glob_patterns.push((glob.compile_matcher(), p.roles.clone()));
        }
    }

    Ok(GroupMappingCompiled {
        direct: cfg.direct.clone(),
        glob_patterns,
        regex_patterns,
        include_all_groups: cfg.include_all_groups,
        role_prefix: cfg.role_prefix.clone(),
        configured,
    })
}

fn permission_matches(permission: &Permission, resource: &ResourceType, action: &Action) -> bool {
    let resource_match = permission.resource == ResourceType::All || permission.resource == *resource;
    if !resource_match {
        return false;
    }

    permission.actions.iter().any(|a| *a == Action::All || *a == *action)
}

fn time_constraint_allows(tc: &TimeConstraint, now: DateTime<Utc>) -> bool {
    if let Some(ref from) = tc.valid_from {
        if let Ok(dt) = DateTime::parse_from_rfc3339(from) {
            if now < dt.with_timezone(&Utc) {
                return false;
            }
        }
    }

    if let Some(ref until) = tc.valid_until {
        if let Ok(dt) = DateTime::parse_from_rfc3339(until) {
            if now > dt.with_timezone(&Utc) {
                return false;
            }
        }
    }

    if let Some(ref hours) = tc.valid_hours {
        let hour = now.hour() as u8;
        if hour < hours.start || hour >= hours.end {
            return false;
        }
    }

    if let Some(ref days) = tc.valid_days {
        let day = now.weekday().num_days_from_sunday() as u8;
        if !days.contains(&day) {
            return false;
        }
    }

    true
}

fn scope_constraint_allows(sc: &ScopeConstraint, scope: Option<&RoleScope>) -> bool {
    let Some(scope) = scope else {
        return false;
    };

    if !sc.scope_types.iter().any(|t| *t == scope.scope_type) {
        return false;
    }

    if let Some(ref values) = sc.scope_values {
        let Some(id) = scope.scope_id.as_deref() else {
            return false;
        };
        if !values.iter().any(|v| v == id) {
            return false;
        }
    }

    true
}

fn attribute_constraint_allows(
    ac: &AttributeConstraint,
    attributes: Option<&serde_json::Value>,
) -> Result<bool> {
    let Some(attrs) = attributes else {
        return Ok(false);
    };
    let value = get_nested_value(attrs, &ac.attribute).unwrap_or(&serde_json::Value::Null);

    Ok(match ac.operator {
        AttributeOperator::Eq => value == &ac.value,
        AttributeOperator::Ne => value != &ac.value,
        AttributeOperator::In => match ac.value {
            serde_json::Value::Array(ref values) => values.iter().any(|v| v == value),
            _ => false,
        },
        AttributeOperator::NotIn => match ac.value {
            serde_json::Value::Array(ref values) => !values.iter().any(|v| v == value),
            _ => false,
        },
        AttributeOperator::Matches => {
            let Some(s) = value.as_str() else {
                return Ok(false);
            };
            let Some(pattern) = ac.value.as_str() else {
                return Ok(false);
            };
            let re = Regex::new(pattern).map_err(|e| RbacError::InvalidConfig(e.to_string()))?;
            re.is_match(s)
        }
    })
}

fn get_nested_value<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = root;
    for part in path.split('.') {
        let serde_json::Value::Object(obj) = cur else {
            return None;
        };
        cur = obj.get(part)?;
    }
    Some(cur)
}

fn builtin_roles(now: String) -> Vec<Role> {
    vec![
        Role {
            id: "super-admin".to_string(),
            name: "Super Administrator".to_string(),
            description: "Full access to all Clawdstrike resources".to_string(),
            permissions: vec![Permission {
                resource: ResourceType::All,
                actions: vec![Action::All],
                constraints: Vec::new(),
            }],
            inherits: Vec::new(),
            scope: None,
            builtin: true,
            metadata: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        Role {
            id: "policy-admin".to_string(),
            name: "Policy Administrator".to_string(),
            description: "Full access to policy management".to_string(),
            permissions: vec![
                Permission {
                    resource: ResourceType::Policy,
                    actions: vec![
                        Action::Create,
                        Action::Read,
                        Action::Update,
                        Action::Delete,
                        Action::Import,
                        Action::Export,
                    ],
                    constraints: Vec::new(),
                },
                Permission {
                    resource: ResourceType::PolicyAssignment,
                    actions: vec![
                        Action::Create,
                        Action::Read,
                        Action::Update,
                        Action::Delete,
                        Action::Assign,
                        Action::Unassign,
                    ],
                    constraints: Vec::new(),
                },
                Permission {
                    resource: ResourceType::Ruleset,
                    actions: vec![Action::Create, Action::Read, Action::Update, Action::Delete],
                    constraints: Vec::new(),
                },
                Permission {
                    resource: ResourceType::Exception,
                    actions: vec![
                        Action::Create,
                        Action::Read,
                        Action::Update,
                        Action::Delete,
                        Action::Grant,
                        Action::Revoke,
                    ],
                    constraints: Vec::new(),
                },
            ],
            inherits: Vec::new(),
            scope: None,
            builtin: true,
            metadata: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        Role {
            id: "policy-contributor".to_string(),
            name: "Policy Contributor".to_string(),
            description: "Can modify policies within assigned scope".to_string(),
            permissions: vec![
                Permission {
                    resource: ResourceType::Policy,
                    actions: vec![Action::Read, Action::Update],
                    constraints: vec![PermissionConstraint::Scope(ScopeConstraint {
                        scope_types: vec![ScopeType::Team, ScopeType::Project],
                        scope_values: None,
                    })],
                },
                Permission {
                    resource: ResourceType::PolicyAssignment,
                    actions: vec![Action::Read, Action::Assign, Action::Unassign],
                    constraints: vec![PermissionConstraint::Scope(ScopeConstraint {
                        scope_types: vec![ScopeType::Team, ScopeType::Project],
                        scope_values: None,
                    })],
                },
            ],
            inherits: Vec::new(),
            scope: None,
            builtin: true,
            metadata: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        Role {
            id: "policy-viewer".to_string(),
            name: "Policy Viewer".to_string(),
            description: "Read-only access to policies".to_string(),
            permissions: vec![
                Permission {
                    resource: ResourceType::Policy,
                    actions: vec![Action::Read],
                    constraints: Vec::new(),
                },
                Permission {
                    resource: ResourceType::PolicyAssignment,
                    actions: vec![Action::Read],
                    constraints: Vec::new(),
                },
                Permission {
                    resource: ResourceType::Ruleset,
                    actions: vec![Action::Read],
                    constraints: Vec::new(),
                },
            ],
            inherits: Vec::new(),
            scope: None,
            builtin: true,
            metadata: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        Role {
            id: "guard-admin".to_string(),
            name: "Guard Administrator".to_string(),
            description: "Full access to guard configuration".to_string(),
            permissions: vec![Permission {
                resource: ResourceType::Guard,
                actions: vec![
                    Action::Create,
                    Action::Read,
                    Action::Update,
                    Action::Delete,
                    Action::Enable,
                    Action::Disable,
                ],
                constraints: Vec::new(),
            }],
            inherits: Vec::new(),
            scope: None,
            builtin: true,
            metadata: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        Role {
            id: "guard-viewer".to_string(),
            name: "Guard Viewer".to_string(),
            description: "Read-only access to guard configuration".to_string(),
            permissions: vec![Permission {
                resource: ResourceType::Guard,
                actions: vec![Action::Read],
                constraints: Vec::new(),
            }],
            inherits: Vec::new(),
            scope: None,
            builtin: true,
            metadata: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        Role {
            id: "audit-viewer".to_string(),
            name: "Audit Viewer".to_string(),
            description: "Read-only access to audit logs".to_string(),
            permissions: vec![Permission {
                resource: ResourceType::AuditLog,
                actions: vec![Action::Read],
                constraints: Vec::new(),
            }],
            inherits: Vec::new(),
            scope: None,
            builtin: true,
            metadata: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        Role {
            id: "audit-admin".to_string(),
            name: "Audit Administrator".to_string(),
            description: "Full access to audit logs".to_string(),
            permissions: vec![
                Permission {
                    resource: ResourceType::AuditLog,
                    actions: vec![Action::Read, Action::Export],
                    constraints: Vec::new(),
                },
                Permission {
                    resource: ResourceType::Session,
                    actions: vec![Action::Read],
                    constraints: Vec::new(),
                },
            ],
            inherits: Vec::new(),
            scope: None,
            builtin: true,
            metadata: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        Role {
            id: "exception-granter".to_string(),
            name: "Exception Granter".to_string(),
            description: "Can grant temporary policy exceptions".to_string(),
            permissions: vec![Permission {
                resource: ResourceType::Exception,
                actions: vec![Action::Create, Action::Read, Action::Grant],
                constraints: vec![
                    PermissionConstraint::Time(TimeConstraint {
                        valid_from: None,
                        valid_until: None,
                        valid_hours: Some(HourRange { start: 9, end: 17 }),
                        valid_days: None,
                    }),
                    PermissionConstraint::Approval(ApprovalConstraint {
                        approver_roles: vec!["policy-admin".to_string()],
                        required_approvals: 1,
                        approval_ttl_secs: 3600,
                    }),
                ],
            }],
            inherits: Vec::new(),
            scope: None,
            builtin: true,
            metadata: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        Role {
            id: "session-manager".to_string(),
            name: "Session Manager".to_string(),
            description: "Can view and terminate sessions".to_string(),
            permissions: vec![Permission {
                resource: ResourceType::Session,
                actions: vec![Action::Read, Action::Delete],
                constraints: Vec::new(),
            }],
            inherits: Vec::new(),
            scope: None,
            builtin: true,
            metadata: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        Role {
            id: "tenant-admin".to_string(),
            name: "Tenant Administrator".to_string(),
            description: "Full access to tenant management".to_string(),
            permissions: vec![
                Permission {
                    resource: ResourceType::Tenant,
                    actions: vec![Action::Create, Action::Read, Action::Update, Action::Delete],
                    constraints: Vec::new(),
                },
                Permission {
                    resource: ResourceType::User,
                    actions: vec![Action::Create, Action::Read, Action::Update, Action::Delete],
                    constraints: Vec::new(),
                },
                Permission {
                    resource: ResourceType::Role,
                    actions: vec![Action::Read, Action::Assign, Action::Unassign],
                    constraints: Vec::new(),
                },
            ],
            inherits: Vec::new(),
            scope: None,
            builtin: true,
            metadata: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity_with_role(role: &str) -> clawdstrike::IdentityPrincipal {
        clawdstrike::IdentityPrincipal {
            id: "user-1".to_string(),
            provider: clawdstrike::IdentityProvider::Oidc,
            issuer: "https://issuer.example".to_string(),
            display_name: None,
            email: None,
            email_verified: None,
            organization_id: Some("org-1".to_string()),
            teams: vec!["team-payments".to_string()],
            roles: vec![role.to_string()],
            attributes: std::collections::HashMap::new(),
            authenticated_at: chrono::Utc::now().to_rfc3339(),
            auth_method: None,
            expires_at: None,
        }
    }

    #[test]
    fn attribute_constraints_match_resource_attributes() {
        let store = Arc::new(InMemoryRbacStore::new());
        let cfg = Arc::new(RbacConfig::default());
        let rbac = RbacManager::new(store.clone(), cfg).expect("rbac");

        let now = chrono::Utc::now().to_rfc3339();
        let role = Role {
            id: "prod-deployer".to_string(),
            name: "Prod Deployer".to_string(),
            description: "Can assign in production".to_string(),
            permissions: vec![Permission {
                resource: ResourceType::PolicyAssignment,
                actions: vec![Action::Assign],
                constraints: vec![PermissionConstraint::Attribute(AttributeConstraint {
                    attribute: "environment".to_string(),
                    operator: AttributeOperator::Eq,
                    value: serde_json::Value::String("production".to_string()),
                })],
            }],
            inherits: Vec::new(),
            scope: None,
            builtin: false,
            metadata: None,
            created_at: now.clone(),
            updated_at: now,
        };
        store.upsert_role(&role).expect("upsert");

        let identity = test_identity_with_role("prod-deployer");

        let allowed = rbac
            .check_permission_for_identity_with_context(
                &identity,
                ResourceRef {
                    resource_type: ResourceType::PolicyAssignment,
                    id: Some("assignment-1".to_string()),
                    attributes: Some(serde_json::json!({"environment": "production"})),
                },
                Action::Assign,
                None,
            )
            .expect("check");
        assert!(allowed.allowed);

        let denied = rbac
            .check_permission_for_identity_with_context(
                &identity,
                ResourceRef {
                    resource_type: ResourceType::PolicyAssignment,
                    id: Some("assignment-1".to_string()),
                    attributes: Some(serde_json::json!({"environment": "staging"})),
                },
                Action::Assign,
                None,
            )
            .expect("check");
        assert!(!denied.allowed);
    }

    #[test]
    fn scope_constraints_require_matching_scope() {
        let store = Arc::new(InMemoryRbacStore::new());
        let cfg = Arc::new(RbacConfig::default());
        let rbac = RbacManager::new(store.clone(), cfg).expect("rbac");

        let now = chrono::Utc::now().to_rfc3339();
        let role = Role {
            id: "team-policy-admin".to_string(),
            name: "Team Policy Admin".to_string(),
            description: "Can update policies in a team scope".to_string(),
            permissions: vec![Permission {
                resource: ResourceType::Policy,
                actions: vec![Action::Update],
                constraints: vec![PermissionConstraint::Scope(ScopeConstraint {
                    scope_types: vec![ScopeType::Team],
                    scope_values: Some(vec!["team-payments".to_string()]),
                })],
            }],
            inherits: Vec::new(),
            scope: None,
            builtin: false,
            metadata: None,
            created_at: now.clone(),
            updated_at: now,
        };
        store.upsert_role(&role).expect("upsert");

        let identity = test_identity_with_role("team-policy-admin");

        let ok = rbac
            .check_permission_for_identity_with_context(
                &identity,
                ResourceRef {
                    resource_type: ResourceType::Policy,
                    id: Some("policy-1".to_string()),
                    attributes: None,
                },
                Action::Update,
                Some(RoleScope {
                    scope_type: ScopeType::Team,
                    scope_id: Some("team-payments".to_string()),
                    include_children: false,
                }),
            )
            .expect("check");
        assert!(ok.allowed);

        let bad = rbac
            .check_permission_for_identity_with_context(
                &identity,
                ResourceRef {
                    resource_type: ResourceType::Policy,
                    id: Some("policy-1".to_string()),
                    attributes: None,
                },
                Action::Update,
                Some(RoleScope {
                    scope_type: ScopeType::Team,
                    scope_id: Some("team-other".to_string()),
                    include_children: false,
                }),
            )
            .expect("check");
        assert!(!bad.allowed);
    }
}

fn dedupe_strings(input: Vec<String>) -> Vec<String> {
    sort_strings(input.into_iter().collect())
}

fn sort_strings(input: HashSet<String>) -> Vec<String> {
    let mut out: Vec<String> = input.into_iter().collect();
    out.sort();
    out
}

// chrono `Datelike/Timelike` helpers
use chrono::{Datelike, Timelike};
