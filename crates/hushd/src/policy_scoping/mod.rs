//! Identity-based policy scoping and resolution.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{Datelike, Timelike, Utc};
use clawdstrike::guards::GuardContext;
use clawdstrike::policy::MergeStrategy;
use clawdstrike::Policy;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::config::{PolicyScopingConfig, PolicyScopingEscalationPreventionConfig};
use crate::control_db::ControlDb;

#[derive(Debug, thiserror::Error)]
pub enum PolicyScopingError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid policy yaml: {0}")]
    InvalidPolicyYaml(String),
    #[error("invalid condition: {0}")]
    InvalidCondition(String),
}

pub type Result<T> = std::result::Result<T, PolicyScopingError>;

/// Policy scope definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyScope {
    #[serde(rename = "type")]
    pub scope_type: PolicyScopeType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<Box<PolicyScope>>,
    #[serde(default)]
    pub conditions: Vec<ScopeCondition>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyScopeType {
    Global,
    Organization,
    Team,
    Project,
    Role,
    User,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScopeCondition {
    IdentityAttribute(IdentityCondition),
    RequestContext(RequestCondition),
    Time(TimeCondition),
    Custom(CustomCondition),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityCondition {
    pub attribute: String,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Eq,
    Ne,
    In,
    NotIn,
    Contains,
    Matches,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeCondition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_hours: Option<HourRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_days: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_range: Option<DateRange>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HourRange {
    pub start: u8,
    pub end: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DateRange {
    pub start: String,
    pub end: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomCondition {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopedPolicy {
    pub id: String,
    pub name: String,
    pub scope: PolicyScope,
    pub priority: i32,
    pub merge_strategy: MergeStrategy,
    pub policy_yaml: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PolicyMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub created_at: String,
    pub updated_at: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyAssignment {
    pub id: String,
    pub policy_id: String,
    pub target: PolicyAssignmentTarget,
    pub priority: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub assigned_by: String,
    pub assigned_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyAssignmentTarget {
    #[serde(rename = "type")]
    pub target_type: PolicyAssignmentTargetType,
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAssignmentTargetType {
    Organization,
    Team,
    Project,
    User,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedPolicy {
    pub policy: Policy,
    pub contributing_policies: Vec<ContributingPolicy>,
    pub resolved_at: String,
    pub cache_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContributingPolicy {
    pub id: String,
    pub name: String,
    pub scope: PolicyScope,
    pub priority: i32,
}

/// Stored metadata fields for scoped policies (persisted in metadata_json).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredPolicyMetadata {
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

pub trait PolicyScopingStore: Send + Sync {
    fn get_scoped_policy(&self, id: &str) -> Result<Option<ScopedPolicy>>;
    fn list_scoped_policies(&self) -> Result<Vec<ScopedPolicy>>;
    fn insert_scoped_policy(&self, policy: &ScopedPolicy) -> Result<()>;
    fn update_scoped_policy(&self, policy: &ScopedPolicy) -> Result<()>;
    fn delete_scoped_policy(&self, id: &str) -> Result<bool>;

    fn insert_assignment(&self, assignment: &PolicyAssignment) -> Result<()>;
    fn list_assignments(&self) -> Result<Vec<PolicyAssignment>>;
    fn delete_assignment(&self, id: &str) -> Result<bool>;
}

#[derive(Clone)]
pub struct SqlitePolicyScopingStore {
    db: Arc<ControlDb>,
}

impl SqlitePolicyScopingStore {
    pub fn new(db: Arc<ControlDb>) -> Self {
        Self { db }
    }
}

impl PolicyScopingStore for SqlitePolicyScopingStore {
    fn get_scoped_policy(&self, id: &str) -> Result<Option<ScopedPolicy>> {
        let conn = self.db.lock_conn();
        let mut stmt = conn.prepare(
            r#"
SELECT name, scope_json, priority, merge_strategy, policy_yaml, enabled, metadata_json, created_at, updated_at
FROM scoped_policies
WHERE id = ?1
            "#,
        )?;

        let mut rows = stmt.query(rusqlite::params![id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        let name: String = row.get(0)?;
        let scope_json: String = row.get(1)?;
        let priority: i32 = row.get(2)?;
        let merge_strategy: String = row.get(3)?;
        let policy_yaml: String = row.get(4)?;
        let enabled: i64 = row.get(5)?;
        let metadata_json: Option<String> = row.get(6)?;
        let created_at: String = row.get(7)?;
        let updated_at: String = row.get(8)?;

        Ok(Some(scoped_policy_from_row(
            id.to_string(),
            name,
            scope_json,
            priority,
            merge_strategy,
            policy_yaml,
            enabled != 0,
            metadata_json,
            created_at,
            updated_at,
        )?))
    }

    fn list_scoped_policies(&self) -> Result<Vec<ScopedPolicy>> {
        let conn = self.db.lock_conn();
        let mut stmt = conn.prepare(
            r#"
SELECT id, name, scope_json, priority, merge_strategy, policy_yaml, enabled, metadata_json, created_at, updated_at
FROM scoped_policies
ORDER BY id ASC
            "#,
        )?;

        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let scope_json: String = row.get(2)?;
            let priority: i32 = row.get(3)?;
            let merge_strategy: String = row.get(4)?;
            let policy_yaml: String = row.get(5)?;
            let enabled: i64 = row.get(6)?;
            let metadata_json: Option<String> = row.get(7)?;
            let created_at: String = row.get(8)?;
            let updated_at: String = row.get(9)?;

            out.push(scoped_policy_from_row(
                id,
                name,
                scope_json,
                priority,
                merge_strategy,
                policy_yaml,
                enabled != 0,
                metadata_json,
                created_at,
                updated_at,
            )?);
        }

        Ok(out)
    }

    fn insert_scoped_policy(&self, policy: &ScopedPolicy) -> Result<()> {
        let conn = self.db.lock_conn();
        let scope_json = serde_json::to_string(&policy.scope)?;
        let metadata_json = policy
            .metadata
            .as_ref()
            .map(|m| {
                serde_json::to_string(&StoredPolicyMetadata {
                    created_by: m.created_by.clone(),
                    description: m.description.clone(),
                    tags: m.tags.clone(),
                })
            })
            .transpose()?;

        conn.execute(
            r#"
INSERT INTO scoped_policies
    (id, name, scope_json, priority, merge_strategy, policy_yaml, enabled, metadata_json, created_at, updated_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            rusqlite::params![
                policy.id,
                policy.name,
                scope_json,
                policy.priority,
                merge_strategy_to_str(&policy.merge_strategy),
                policy.policy_yaml,
                if policy.enabled { 1 } else { 0 },
                metadata_json,
                policy
                    .metadata
                    .as_ref()
                    .map(|m| m.created_at.clone())
                    .unwrap_or_else(|| Utc::now().to_rfc3339()),
                policy
                    .metadata
                    .as_ref()
                    .map(|m| m.updated_at.clone())
                    .unwrap_or_else(|| Utc::now().to_rfc3339())
            ],
        )?;
        Ok(())
    }

    fn update_scoped_policy(&self, policy: &ScopedPolicy) -> Result<()> {
        let conn = self.db.lock_conn();
        let scope_json = serde_json::to_string(&policy.scope)?;
        let metadata_json = policy
            .metadata
            .as_ref()
            .map(|m| {
                serde_json::to_string(&StoredPolicyMetadata {
                    created_by: m.created_by.clone(),
                    description: m.description.clone(),
                    tags: m.tags.clone(),
                })
            })
            .transpose()?;

        conn.execute(
            r#"
UPDATE scoped_policies
SET name = ?2,
    scope_json = ?3,
    priority = ?4,
    merge_strategy = ?5,
    policy_yaml = ?6,
    enabled = ?7,
    metadata_json = ?8,
    updated_at = ?9
WHERE id = ?1
            "#,
            rusqlite::params![
                policy.id,
                policy.name,
                scope_json,
                policy.priority,
                merge_strategy_to_str(&policy.merge_strategy),
                policy.policy_yaml,
                if policy.enabled { 1 } else { 0 },
                metadata_json,
                policy
                    .metadata
                    .as_ref()
                    .map(|m| m.updated_at.clone())
                    .unwrap_or_else(|| Utc::now().to_rfc3339())
            ],
        )?;

        Ok(())
    }

    fn delete_scoped_policy(&self, id: &str) -> Result<bool> {
        let conn = self.db.lock_conn();
        let changed =
            conn.execute("DELETE FROM scoped_policies WHERE id = ?1", rusqlite::params![id])?;
        Ok(changed > 0)
    }

    fn insert_assignment(&self, assignment: &PolicyAssignment) -> Result<()> {
        let conn = self.db.lock_conn();
        conn.execute(
            r#"
INSERT INTO policy_assignments
    (id, policy_id, target_type, target_id, priority, effective_from, effective_until, assigned_by, assigned_at, reason)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            rusqlite::params![
                assignment.id,
                assignment.policy_id,
                policy_assignment_target_type_to_str(&assignment.target.target_type),
                assignment.target.id,
                assignment.priority,
                assignment.effective_from,
                assignment.effective_until,
                assignment.assigned_by,
                assignment.assigned_at,
                assignment.reason
            ],
        )?;
        Ok(())
    }

    fn list_assignments(&self) -> Result<Vec<PolicyAssignment>> {
        let conn = self.db.lock_conn();
        let mut stmt = conn.prepare(
            r#"
SELECT id, policy_id, target_type, target_id, priority, effective_from, effective_until, assigned_by, assigned_at, reason
FROM policy_assignments
ORDER BY assigned_at DESC
            "#,
        )?;

        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let policy_id: String = row.get(1)?;
            let target_type: String = row.get(2)?;
            let target_id: String = row.get(3)?;
            let priority: i32 = row.get(4)?;
            let effective_from: Option<String> = row.get(5)?;
            let effective_until: Option<String> = row.get(6)?;
            let assigned_by: String = row.get(7)?;
            let assigned_at: String = row.get(8)?;
            let reason: Option<String> = row.get(9)?;

            out.push(PolicyAssignment {
                id,
                policy_id,
                target: PolicyAssignmentTarget {
                    target_type: policy_assignment_target_type_from_str(&target_type).unwrap_or(PolicyAssignmentTargetType::Organization),
                    id: target_id,
                },
                priority,
                effective_from,
                effective_until,
                assigned_by,
                assigned_at,
                reason,
            });
        }

        Ok(out)
    }

    fn delete_assignment(&self, id: &str) -> Result<bool> {
        let conn = self.db.lock_conn();
        let changed =
            conn.execute("DELETE FROM policy_assignments WHERE id = ?1", rusqlite::params![id])?;
        Ok(changed > 0)
    }
}

fn scoped_policy_from_row(
    id: String,
    name: String,
    scope_json: String,
    priority: i32,
    merge_strategy: String,
    policy_yaml: String,
    enabled: bool,
    metadata_json: Option<String>,
    created_at: String,
    updated_at: String,
) -> Result<ScopedPolicy> {
    let scope: PolicyScope = serde_json::from_str(&scope_json)?;
    let merge_strategy = merge_strategy_from_str(&merge_strategy);
    let stored_meta: Option<StoredPolicyMetadata> = metadata_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?;

    let metadata = stored_meta.map(|m| PolicyMetadata {
        created_at,
        updated_at,
        created_by: m.created_by,
        description: m.description,
        tags: m.tags,
    });

    Ok(ScopedPolicy {
        id,
        name,
        scope,
        priority,
        merge_strategy,
        policy_yaml,
        enabled,
        metadata,
    })
}

fn merge_strategy_to_str(strategy: &MergeStrategy) -> &'static str {
    match strategy {
        MergeStrategy::Replace => "replace",
        MergeStrategy::Merge => "merge",
        MergeStrategy::DeepMerge => "deep_merge",
    }
}

fn merge_strategy_from_str(value: &str) -> MergeStrategy {
    match value {
        "replace" => MergeStrategy::Replace,
        "merge" => MergeStrategy::Merge,
        "deep_merge" => MergeStrategy::DeepMerge,
        other => {
            tracing::warn!(merge_strategy = %other, "Unknown merge_strategy; defaulting to deep_merge");
            MergeStrategy::DeepMerge
        }
    }
}

fn policy_assignment_target_type_to_str(value: &PolicyAssignmentTargetType) -> &'static str {
    match value {
        PolicyAssignmentTargetType::Organization => "organization",
        PolicyAssignmentTargetType::Team => "team",
        PolicyAssignmentTargetType::Project => "project",
        PolicyAssignmentTargetType::User => "user",
    }
}

fn policy_assignment_target_type_from_str(value: &str) -> Option<PolicyAssignmentTargetType> {
    match value {
        "organization" => Some(PolicyAssignmentTargetType::Organization),
        "team" => Some(PolicyAssignmentTargetType::Team),
        "project" => Some(PolicyAssignmentTargetType::Project),
        "user" => Some(PolicyAssignmentTargetType::User),
        _ => None,
    }
}

pub struct PolicyResolver {
    store: Arc<dyn PolicyScopingStore>,
    config: Arc<PolicyScopingConfig>,
    custom_conditions: Arc<HashMap<String, Arc<dyn CustomConditionEvaluator>>>,
}

pub trait CustomConditionEvaluator: Send + Sync {
    fn evaluate(&self, context: &GuardContext, params: Option<&HashMap<String, serde_json::Value>>) -> bool;
}

impl PolicyResolver {
    pub fn new(
        store: Arc<dyn PolicyScopingStore>,
        config: Arc<PolicyScopingConfig>,
        custom_conditions: Option<HashMap<String, Arc<dyn CustomConditionEvaluator>>>,
    ) -> Self {
        Self {
            store,
            config,
            custom_conditions: Arc::new(custom_conditions.unwrap_or_default()),
        }
    }

    pub fn store(&self) -> &Arc<dyn PolicyScopingStore> {
        &self.store
    }

    pub fn resolve_policy(&self, default_policy: &Policy, context: &GuardContext) -> Result<ResolvedPolicy> {
        if !self.config.enabled {
            return Ok(ResolvedPolicy {
                policy: default_policy.clone(),
                contributing_policies: Vec::new(),
                resolved_at: Utc::now().to_rfc3339(),
                cache_key: "policy_scoping_disabled".to_string(),
            });
        }

        let all = self.store.list_scoped_policies()?;
        let mut matching = Vec::new();
        for p in all {
            if !p.enabled {
                continue;
            }
            if scope_matches_context(&p.scope, context) {
                matching.push(p);
            }
        }

        matching.sort_by(|a, b| {
            let a_order = scope_order(&a.scope.scope_type);
            let b_order = scope_order(&b.scope.scope_type);
            a_order
                .cmp(&b_order)
                .then_with(|| a.priority.cmp(&b.priority))
                .then_with(|| a.id.cmp(&b.id))
        });

        let mut merged = default_policy.clone();
        let mut contributing = Vec::new();

        for scoped in matching {
            if !evaluate_conditions(&scoped.scope.conditions, context, &self.custom_conditions)? {
                continue;
            }

            // Parse the policy overlay.
            let mut child = Policy::from_yaml(&scoped.policy_yaml)
                .map_err(|e| PolicyScopingError::InvalidPolicyYaml(e.to_string()))?;

            // Force merge strategy from scoped policy record.
            child.merge_strategy = scoped.merge_strategy.clone();

            if self.config.escalation_prevention.enabled {
                validate_policy_escalation(&child, &merged, &self.config.escalation_prevention)?;
            }

            merged = merged.merge(&child);
            contributing.push(ContributingPolicy {
                id: scoped.id.clone(),
                name: scoped.name.clone(),
                scope: scoped.scope.clone(),
                priority: scoped.priority,
            });
        }

        // Cache key is for resolvers/clients; hash in a stable way based on the result.
        let cache_key = {
            let payload = serde_json::json!({
                "default_policy": hush_core::sha256(default_policy.to_yaml().unwrap_or_default().as_bytes()).to_hex(),
                "identity": context.identity.as_ref().map(|i| serde_json::to_value(i).unwrap_or(serde_json::Value::Null)),
                "roles": context.roles,
                "teams": context.identity.as_ref().map(|i| &i.teams),
                "contributing": contributing.iter().map(|p| (&p.id, p.priority)).collect::<Vec<_>>(),
            });
            hush_core::sha256(payload.to_string().as_bytes()).to_hex()
        };

        Ok(ResolvedPolicy {
            policy: merged,
            contributing_policies: contributing,
            resolved_at: Utc::now().to_rfc3339(),
            cache_key,
        })
    }
}

fn scope_order(scope_type: &PolicyScopeType) -> u8 {
    match scope_type {
        PolicyScopeType::Global => 0,
        PolicyScopeType::Organization => 1,
        PolicyScopeType::Team => 2,
        PolicyScopeType::Project => 3,
        PolicyScopeType::Role => 4,
        PolicyScopeType::User => 5,
    }
}

fn scope_matches_context(scope: &PolicyScope, context: &GuardContext) -> bool {
    match scope.scope_type {
        PolicyScopeType::Global => true,
        PolicyScopeType::Organization => {
            let Some(id) = scope.id.as_deref() else {
                return false;
            };
            context
                .organization
                .as_ref()
                .map(|o| o.id.as_str() == id)
                .unwrap_or_else(|| {
                    context
                        .identity
                        .as_ref()
                        .and_then(|i| i.organization_id.as_deref())
                        .is_some_and(|org| org == id)
                })
        }
        PolicyScopeType::Team => {
            let Some(id) = scope.id.as_deref() else {
                return false;
            };
            context
                .identity
                .as_ref()
                .map(|i| i.teams.iter().any(|t| t == id))
                .unwrap_or(false)
        }
        PolicyScopeType::Project => {
            let Some(id) = scope.id.as_deref() else {
                return false;
            };

            let state = context
                .session
                .as_ref()
                .and_then(|s| s.state.as_ref())
                .cloned()
                .unwrap_or_default();

            state
                .get("projectId")
                .or_else(|| state.get("project_id"))
                .and_then(|v| v.as_str())
                .is_some_and(|pid| pid == id)
        }
        PolicyScopeType::Role => {
            let Some(id) = scope.id.as_deref() else {
                return false;
            };
            context
                .roles
                .as_ref()
                .map(|roles| roles.iter().any(|r| r == id))
                .or_else(|| {
                    context
                        .identity
                        .as_ref()
                        .map(|i| i.roles.iter().any(|r| r == id))
                })
                .unwrap_or(false)
        }
        PolicyScopeType::User => {
            let Some(id) = scope.id.as_deref() else {
                return false;
            };
            context
                .identity
                .as_ref()
                .map(|i| i.id == id)
                .unwrap_or(false)
        }
    }
}

fn evaluate_conditions(
    conditions: &[ScopeCondition],
    context: &GuardContext,
    custom_conditions: &HashMap<String, Arc<dyn CustomConditionEvaluator>>,
) -> Result<bool> {
    if conditions.is_empty() {
        return Ok(true);
    }

    for c in conditions {
        let ok = match c {
            ScopeCondition::IdentityAttribute(cond) => evaluate_identity_condition(cond, context)?,
            ScopeCondition::RequestContext(cond) => evaluate_request_condition(cond, context)?,
            ScopeCondition::Time(cond) => evaluate_time_condition(cond)?,
            ScopeCondition::Custom(cond) => {
                let Some(eval) = custom_conditions.get(&cond.name) else {
                    // Fail closed: unknown custom condition means it does not match.
                    return Ok(false);
                };
                eval.evaluate(context, cond.params.as_ref())
            }
        };

        if !ok {
            return Ok(false);
        }
    }

    Ok(true)
}

fn evaluate_identity_condition(cond: &IdentityCondition, context: &GuardContext) -> Result<bool> {
    let Some(identity) = context.identity.as_ref() else {
        return Ok(false);
    };

    let identity_val = serde_json::to_value(identity)?;
    let value = get_nested_value(&identity_val, &cond.attribute).unwrap_or(&serde_json::Value::Null);
    eval_operator(value, &cond.operator, &cond.value)
}

fn evaluate_request_condition(cond: &RequestCondition, context: &GuardContext) -> Result<bool> {
    let Some(request) = context.request.as_ref() else {
        return Ok(false);
    };
    let request_val = serde_json::to_value(request)?;
    let normalized = normalize_request_field(&cond.field);
    let value = get_nested_value(&request_val, &normalized).unwrap_or(&serde_json::Value::Null);
    eval_operator(value, &cond.operator, &cond.value)
}

fn normalize_request_field(field: &str) -> String {
    // Accept either camelCase (spec) or snake_case (Rust structs).
    let field = field.trim();
    if field.is_empty() {
        return field.to_string();
    }

    let mut parts: Vec<&str> = field.split('.').collect();
    for p in &mut parts {
        *p = match *p {
            "sourceIp" => "source_ip",
            "geoLocation" => "geo_location",
            "userAgent" => "user_agent",
            "isVpn" => "is_vpn",
            "isCorporateNetwork" => "is_corporate_network",
            other => other,
        };
    }
    parts.join(".")
}

fn evaluate_time_condition(cond: &TimeCondition) -> Result<bool> {
    // Only IANA timezones are supported; unknown zones fail closed.
    let now_utc = Utc::now();

    let now = if let Some(tz) = cond.timezone.as_deref() {
        let tz: chrono_tz::Tz = tz
            .parse()
            .map_err(|_| PolicyScopingError::InvalidCondition(format!("invalid timezone {tz}")))?;
        now_utc.with_timezone(&tz)
    } else {
        now_utc.with_timezone(&chrono_tz::UTC)
    };

    if let Some(ref hours) = cond.valid_hours {
        let hour = now.hour() as u8;
        if hour < hours.start || hour >= hours.end {
            return Ok(false);
        }
    }

    if let Some(ref days) = cond.valid_days {
        let day = now.weekday().num_days_from_sunday() as u8;
        if !days.contains(&day) {
            return Ok(false);
        }
    }

    if let Some(ref range) = cond.date_range {
        let start = chrono::DateTime::parse_from_rfc3339(&range.start)
            .map_err(|e| PolicyScopingError::InvalidCondition(format!("invalid date_range.start: {e}")))?;
        let end = chrono::DateTime::parse_from_rfc3339(&range.end)
            .map_err(|e| PolicyScopingError::InvalidCondition(format!("invalid date_range.end: {e}")))?;

        if now_utc < start.with_timezone(&Utc) || now_utc > end.with_timezone(&Utc) {
            return Ok(false);
        }
    }

    Ok(true)
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

fn eval_operator(actual: &serde_json::Value, op: &ConditionOperator, expected: &serde_json::Value) -> Result<bool> {
    Ok(match op {
        ConditionOperator::Eq => actual == expected,
        ConditionOperator::Ne => actual != expected,
        ConditionOperator::In => match expected {
            serde_json::Value::Array(values) => values.iter().any(|v| v == actual),
            _ => false,
        },
        ConditionOperator::NotIn => match expected {
            serde_json::Value::Array(values) => !values.iter().any(|v| v == actual),
            _ => false,
        },
        ConditionOperator::Contains => match actual {
            serde_json::Value::Array(values) => values.iter().any(|v| v == expected),
            _ => false,
        },
        ConditionOperator::Matches => {
            let Some(s) = actual.as_str() else {
                return Ok(false);
            };
            let Some(pattern) = expected.as_str() else {
                return Ok(false);
            };
            let re = Regex::new(pattern).map_err(|e| {
                PolicyScopingError::InvalidCondition(format!("invalid regex {pattern}: {e}"))
            })?;
            re.is_match(s)
        }
    })
}

fn validate_policy_escalation(
    child: &Policy,
    parent: &Policy,
    cfg: &PolicyScopingEscalationPreventionConfig,
) -> Result<()> {
    if cfg.locked_fields.is_empty() {
        return Ok(());
    }

    // Only enforce a subset of known "locked fields" from the spec.
    for field in &cfg.locked_fields {
        match field.as_str() {
            "guards.forbidden_path.patterns" => {
                if let (Some(parent_cfg), Some(child_cfg)) = (
                    parent.guards.forbidden_path.as_ref(),
                    child.guards.forbidden_path.as_ref(),
                ) {
                    let parent_patterns = parent_cfg.effective_patterns();
                    for removed in &child_cfg.remove_patterns {
                        if parent_patterns.iter().any(|p| p == removed) {
                            return Err(PolicyScopingError::InvalidCondition(format!(
                                "escalation_prevention: cannot remove forbidden pattern {removed}"
                            )));
                        }
                    }
                }
            }
            "guards.mcp_tool.block" => {
                if let (Some(parent_cfg), Some(child_cfg)) =
                    (parent.guards.mcp_tool.as_ref(), child.guards.mcp_tool.as_ref())
                {
                    for removed in &child_cfg.remove_block {
                        if parent_cfg.block.iter().any(|t| t == removed) {
                            return Err(PolicyScopingError::InvalidCondition(format!(
                                "escalation_prevention: cannot remove blocked tool {removed}"
                            )));
                        }
                    }
                }
            }
            "guards.egress_allowlist.block" => {
                if let (Some(parent_cfg), Some(child_cfg)) = (
                    parent.guards.egress_allowlist.as_ref(),
                    child.guards.egress_allowlist.as_ref(),
                ) {
                    for removed in &child_cfg.remove_block {
                        if parent_cfg.block.iter().any(|d| d == removed) {
                            return Err(PolicyScopingError::InvalidCondition(format!(
                                "escalation_prevention: cannot remove blocked domain {removed}"
                            )));
                        }
                    }
                }
            }
            "guards.secret_leak.patterns" => {
                if child.guards.secret_leak.is_some() {
                    return Err(PolicyScopingError::InvalidCondition(
                        "escalation_prevention: cannot override secret_leak patterns".to_string(),
                    ));
                }
            }
            _ => {
                // Unknown field locks are ignored for now (conservative).
            }
        }
    }

    Ok(())
}
