//! Shared policy distribution utilities for cloud-side deploy and backfill flows.
//!
//! This module provides:
//! - Tenant-level active policy persistence (`tenant_active_policies`)
//! - Canonical policy sync bucket/key naming
//! - Agent KV writes/backfill reconciliation

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::executor::Executor;
use sqlx::row::Row;
use sqlx_postgres::Postgres;
use std::collections::HashSet;
use uuid::Uuid;

use crate::db::PgPool;
use crate::services::tenant_provisioner::tenant_subject_prefix;

pub const POLICY_SYNC_KEY: &str = "policy.yaml";

const POLICY_SYNC_EPOCH_YAML_PATHS: &[&[&str]] = &[
    &["policy_epoch"],
    &["policyEpoch"],
    &["epoch"],
    &["policy", "epoch"],
    &["policy", "policy_epoch"],
    &["policy", "policyEpoch"],
    &["metadata", "policy_epoch"],
    &["metadata", "policyEpoch"],
    &["bundle", "epoch"],
    &["bundle", "policy_epoch"],
    &["bundle", "policyEpoch"],
];

#[derive(Debug, Clone)]
pub struct ActiveTenantPolicy {
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub policy_yaml: String,
    pub checksum_sha256: String,
    pub description: Option<String>,
    pub version: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct EffectiveAgentPolicy {
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub agent_id: String,
    pub principal_id: Option<Uuid>,
    pub lifecycle_state: String,
    pub liveness_state: Option<String>,
    pub policy_yaml: String,
    pub checksum_sha256: String,
    pub policy_epoch: i64,
    pub source_attachments: Vec<EffectivePolicyAttachment>,
    pub applied_overlays: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EffectivePolicyAttachment {
    pub attachment_id: Uuid,
    pub target_kind: String,
    pub target_id: Uuid,
    pub priority: i32,
    pub policy_ref: Option<String>,
    pub checksum_sha256: Option<String>,
}

pub fn policy_update_subject(tenant_slug: &str) -> String {
    format!("{}.policy.update", tenant_subject_prefix(tenant_slug))
}

pub fn policy_sync_bucket(subject_prefix: &str, agent_id: &str) -> String {
    format!(
        "{}-policy-sync-{}",
        sanitize_bucket_component(subject_prefix),
        sanitize_bucket_component(agent_id)
    )
}

fn sanitize_bucket_component(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn checksum_sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn policy_yaml_checksum_sha256(policy_yaml: &str) -> String {
    checksum_sha256_hex(policy_yaml)
}

pub fn validate_policy_document(policy_yaml: &str) -> Result<(), String> {
    let policy_root = serde_yaml::from_str::<serde_yaml::Value>(policy_yaml)
        .map_err(|err| format!("invalid policy YAML: {err}"))?;
    if !matches!(policy_root, serde_yaml::Value::Mapping(_)) {
        return Err("policy YAML root must be a mapping".to_string());
    }
    Ok(())
}

pub async fn upsert_active_policy(
    db: &PgPool,
    tenant_id: Uuid,
    policy_yaml: &str,
    description: Option<&str>,
) -> Result<ActiveTenantPolicy, sqlx::error::Error> {
    upsert_active_policy_with_executor(db, tenant_id, policy_yaml, description).await
}

pub async fn upsert_active_policy_with_executor<'e, E>(
    executor: E,
    tenant_id: Uuid,
    policy_yaml: &str,
    description: Option<&str>,
) -> Result<ActiveTenantPolicy, sqlx::error::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    let checksum = checksum_sha256_hex(policy_yaml);
    let row = sqlx::query::query(
        r#"WITH upsert AS (
               INSERT INTO tenant_active_policies (
                   tenant_id,
                   policy_yaml,
                   checksum_sha256,
                   description,
                   version
               )
               VALUES ($1, $2, $3, $4, 1)
               ON CONFLICT (tenant_id) DO UPDATE
               SET policy_yaml = EXCLUDED.policy_yaml,
                   checksum_sha256 = EXCLUDED.checksum_sha256,
                   description = EXCLUDED.description,
                   version = tenant_active_policies.version + 1,
                   updated_at = now()
               RETURNING tenant_id, policy_yaml, checksum_sha256, description, version, updated_at
           )
           SELECT u.tenant_id,
                  t.slug AS tenant_slug,
                  u.policy_yaml,
                  u.checksum_sha256,
                  u.description,
                  u.version,
                  u.updated_at
           FROM upsert AS u
           JOIN tenants AS t
             ON t.id = u.tenant_id"#,
    )
    .bind(tenant_id)
    .bind(policy_yaml)
    .bind(checksum)
    .bind(description)
    .fetch_one(executor)
    .await?;

    row_to_active_policy(row)
}

pub async fn upsert_active_policy_after_version_with_executor<'e, E>(
    executor: E,
    tenant_id: Uuid,
    policy_yaml: &str,
    description: Option<&str>,
    expected_base_version: i64,
) -> Result<Option<ActiveTenantPolicy>, sqlx::error::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    let checksum = checksum_sha256_hex(policy_yaml);
    let row = sqlx::query::query(
        r#"WITH updated AS (
               UPDATE tenant_active_policies
               SET policy_yaml = $2,
                   checksum_sha256 = $3,
                   description = $4,
                   version = tenant_active_policies.version + 1,
                   updated_at = now()
               WHERE tenant_id = $1
                 AND version = $5
               RETURNING tenant_id, policy_yaml, checksum_sha256, description, version, updated_at
           ),
           inserted AS (
               INSERT INTO tenant_active_policies (
                   tenant_id,
                   policy_yaml,
                   checksum_sha256,
                   description,
                   version
               )
               SELECT $1, $2, $3, $4, 1
               WHERE $5 = 0
                 AND NOT EXISTS (
                     SELECT 1
                     FROM tenant_active_policies
                     WHERE tenant_id = $1
                 )
               ON CONFLICT (tenant_id) DO NOTHING
               RETURNING tenant_id, policy_yaml, checksum_sha256, description, version, updated_at
           ),
           upsert AS (
               SELECT *
               FROM updated
               UNION ALL
               SELECT *
               FROM inserted
           )
           SELECT u.tenant_id,
                  t.slug AS tenant_slug,
                  u.policy_yaml,
                  u.checksum_sha256,
                  u.description,
                  u.version,
                  u.updated_at
           FROM upsert AS u
           JOIN tenants AS t
             ON t.id = u.tenant_id"#,
    )
    .bind(tenant_id)
    .bind(policy_yaml)
    .bind(checksum)
    .bind(description)
    .bind(expected_base_version)
    .fetch_optional(executor)
    .await?;

    row.map(row_to_active_policy).transpose()
}

pub async fn fetch_active_policy_by_tenant_id(
    db: &PgPool,
    tenant_id: Uuid,
) -> Result<Option<ActiveTenantPolicy>, sqlx::error::Error> {
    fetch_active_policy_by_tenant_id_with_executor(db, tenant_id).await
}

pub async fn fetch_active_policy_by_tenant_id_with_executor<'e, E>(
    executor: E,
    tenant_id: Uuid,
) -> Result<Option<ActiveTenantPolicy>, sqlx::error::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query::query(
        r#"SELECT p.tenant_id,
                  t.slug AS tenant_slug,
                  p.policy_yaml,
                  p.checksum_sha256,
                  p.description,
                  p.version,
                  p.updated_at
           FROM tenant_active_policies AS p
           JOIN tenants AS t
             ON t.id = p.tenant_id
           WHERE p.tenant_id = $1"#,
    )
    .bind(tenant_id)
    .fetch_optional(executor)
    .await?;

    row.map(row_to_active_policy).transpose()
}

pub async fn fetch_active_policy_by_tenant_id_for_update_with_executor<'e, E>(
    executor: E,
    tenant_id: Uuid,
) -> Result<Option<ActiveTenantPolicy>, sqlx::error::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query::query(
        r#"SELECT p.tenant_id,
                  t.slug AS tenant_slug,
                  p.policy_yaml,
                  p.checksum_sha256,
                  p.description,
                  p.version,
                  p.updated_at
           FROM tenant_active_policies AS p
           JOIN tenants AS t
             ON t.id = p.tenant_id
           WHERE p.tenant_id = $1
           FOR UPDATE OF p"#,
    )
    .bind(tenant_id)
    .fetch_optional(executor)
    .await?;

    row.map(row_to_active_policy).transpose()
}

pub async fn fetch_active_policy_by_tenant_slug(
    db: &PgPool,
    tenant_slug: &str,
) -> Result<Option<ActiveTenantPolicy>, sqlx::error::Error> {
    let row = sqlx::query::query(
        r#"SELECT p.tenant_id,
                  t.slug AS tenant_slug,
                  p.policy_yaml,
                  p.checksum_sha256,
                  p.description,
                  p.version,
                  p.updated_at
           FROM tenant_active_policies AS p
           JOIN tenants AS t
             ON t.id = p.tenant_id
           WHERE t.slug = $1"#,
    )
    .bind(tenant_slug)
    .fetch_optional(db)
    .await?;

    row.map(row_to_active_policy).transpose()
}

pub async fn preview_active_policy_candidate(
    db: &PgPool,
    tenant_id: Uuid,
    policy_yaml: &str,
    description: Option<&str>,
) -> Result<ActiveTenantPolicy, String> {
    validate_policy_document(policy_yaml)?;
    let tenant_slug = fetch_tenant_slug_by_id(db, tenant_id)
        .await
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("tenant {tenant_id} was not found"))?;
    let current_version = fetch_active_policy_by_tenant_id(db, tenant_id)
        .await
        .map_err(|err| err.to_string())?
        .map(|policy| policy.version)
        .unwrap_or(0);
    let next_version = current_version
        .checked_add(1)
        .ok_or_else(|| format!("active policy version {current_version} cannot be incremented"))?;

    Ok(ActiveTenantPolicy {
        tenant_id,
        tenant_slug,
        policy_yaml: policy_yaml.to_string(),
        checksum_sha256: checksum_sha256_hex(policy_yaml),
        description: description.map(str::to_string),
        version: next_version,
        updated_at: Utc::now(),
    })
}

pub async fn put_policy_for_agent(
    nats: &async_nats::Client,
    tenant_slug: &str,
    agent_id: &str,
    policy: &ActiveTenantPolicy,
) -> Result<(), String> {
    let policy_yaml = distribution_policy_yaml(policy)?;
    put_policy_yaml_for_agent(nats, tenant_slug, agent_id, &policy_yaml).await
}

pub async fn put_effective_policy_for_agent(
    nats: &async_nats::Client,
    policy: &EffectiveAgentPolicy,
) -> Result<(), String> {
    put_policy_yaml_for_agent(
        nats,
        &policy.tenant_slug,
        &policy.agent_id,
        &policy.policy_yaml,
    )
    .await
}

async fn put_policy_yaml_for_agent(
    nats: &async_nats::Client,
    tenant_slug: &str,
    agent_id: &str,
    policy_yaml: &str,
) -> Result<(), String> {
    let js = async_nats::jetstream::new(nats.clone());
    let bucket = policy_sync_bucket(&tenant_subject_prefix(tenant_slug), agent_id);
    let store = spine::nats_transport::ensure_kv(&js, &bucket, 1)
        .await
        .map_err(|err| err.to_string())?;
    store
        .put(
            POLICY_SYNC_KEY.to_string(),
            policy_yaml.as_bytes().to_vec().into(),
        )
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

pub async fn reconcile_policy_for_agent(
    nats: &async_nats::Client,
    policy: &ActiveTenantPolicy,
    agent_id: &str,
) -> Result<bool, String> {
    let policy_yaml = distribution_policy_yaml(policy)?;
    reconcile_policy_yaml_for_agent(nats, &policy.tenant_slug, agent_id, &policy_yaml).await
}

pub async fn reconcile_effective_policy_for_agent(
    db: &PgPool,
    nats: &async_nats::Client,
    tenant_id: Uuid,
    agent_id: &str,
) -> Result<bool, String> {
    let Some(policy) = resolve_effective_policy_for_agent(db, tenant_id, agent_id).await? else {
        return Ok(false);
    };
    reconcile_effective_policy_yaml_for_agent(
        nats,
        &policy.tenant_slug,
        &policy.agent_id,
        &policy.policy_yaml,
    )
    .await
}

async fn reconcile_policy_yaml_for_agent(
    nats: &async_nats::Client,
    tenant_slug: &str,
    agent_id: &str,
    policy_yaml: &str,
) -> Result<bool, String> {
    let js = async_nats::jetstream::new(nats.clone());
    let bucket = policy_sync_bucket(&tenant_subject_prefix(tenant_slug), agent_id);
    let store = spine::nats_transport::ensure_kv(&js, &bucket, 1)
        .await
        .map_err(|err| err.to_string())?;

    let expected_bytes = policy_yaml.as_bytes();
    let should_update = match store
        .get(POLICY_SYNC_KEY)
        .await
        .map_err(|err| err.to_string())?
    {
        Some(existing) => existing.as_ref() != expected_bytes,
        None => true,
    };
    if !should_update {
        return Ok(false);
    }

    store
        .put(POLICY_SYNC_KEY.to_string(), expected_bytes.to_vec().into())
        .await
        .map_err(|err| err.to_string())?;
    Ok(true)
}

async fn reconcile_effective_policy_yaml_for_agent(
    nats: &async_nats::Client,
    tenant_slug: &str,
    agent_id: &str,
    policy_yaml: &str,
) -> Result<bool, String> {
    let js = async_nats::jetstream::new(nats.clone());
    let bucket = policy_sync_bucket(&tenant_subject_prefix(tenant_slug), agent_id);
    let store = spine::nats_transport::ensure_kv(&js, &bucket, 1)
        .await
        .map_err(|err| err.to_string())?;

    let existing = store
        .get(POLICY_SYNC_KEY)
        .await
        .map_err(|err| err.to_string())?;
    let mut expected_policy_yaml = policy_yaml.to_string();
    if let Some(existing) = existing.as_ref() {
        if existing.as_ref() == expected_policy_yaml.as_bytes() {
            return Ok(false);
        }
        if policy_yaml_content_matches_ignoring_epoch(
            expected_policy_yaml.as_bytes(),
            existing.as_ref(),
        ) && !candidate_policy_epoch_advances_existing(&expected_policy_yaml, existing.as_ref())?
        {
            return Ok(false);
        }
        expected_policy_yaml =
            policy_yaml_with_epoch_after_existing(&expected_policy_yaml, existing.as_ref())?;
    } else if policy_epoch_from_yaml(expected_policy_yaml.as_bytes()).is_none() {
        return Err("effective policy is missing policy_epoch".to_string());
    }

    store
        .put(
            POLICY_SYNC_KEY.to_string(),
            expected_policy_yaml.as_bytes().to_vec().into(),
        )
        .await
        .map_err(|err| err.to_string())?;
    Ok(true)
}

fn candidate_policy_epoch_advances_existing(
    candidate_policy_yaml: &str,
    existing_policy_yaml: &[u8],
) -> Result<bool, String> {
    let candidate_epoch = policy_epoch_from_yaml(candidate_policy_yaml.as_bytes())
        .ok_or_else(|| "effective policy is missing policy_epoch".to_string())?;
    let Some(existing_epoch) = policy_epoch_from_yaml(existing_policy_yaml) else {
        return Ok(true);
    };
    Ok(candidate_epoch > existing_epoch)
}

fn policy_yaml_with_epoch_after_existing(
    candidate_policy_yaml: &str,
    existing_policy_yaml: &[u8],
) -> Result<String, String> {
    let Some(existing_epoch) = policy_epoch_from_yaml(existing_policy_yaml) else {
        return Ok(candidate_policy_yaml.to_string());
    };
    let candidate_epoch = policy_epoch_from_yaml(candidate_policy_yaml.as_bytes())
        .ok_or_else(|| "effective policy is missing policy_epoch".to_string())?;
    if candidate_epoch > existing_epoch {
        return Ok(candidate_policy_yaml.to_string());
    }
    let next_epoch = existing_epoch
        .checked_add(1)
        .ok_or_else(|| format!("policy epoch {existing_epoch} cannot be incremented"))?;
    stamp_policy_epoch(candidate_policy_yaml, next_epoch)
}

pub fn distribution_policy_yaml(policy: &ActiveTenantPolicy) -> Result<String, String> {
    let policy_epoch = u64::try_from(policy.version).map_err(|_| {
        format!(
            "active policy version {} is not a valid epoch",
            policy.version
        )
    })?;
    stamp_policy_epoch(&policy.policy_yaml, policy_epoch)
}

pub async fn resolve_effective_policy_for_agent(
    db: &PgPool,
    tenant_id: Uuid,
    agent_id: &str,
) -> Result<Option<EffectiveAgentPolicy>, String> {
    let Some(agent) = fetch_policy_agent_context(db, tenant_id, agent_id).await? else {
        return Ok(None);
    };
    let active_policy = fetch_active_policy_by_tenant_id(db, tenant_id)
        .await
        .map_err(|err| err.to_string())?;

    let membership_scope = fetch_principal_membership_scope(db, tenant_id, agent.principal_id)
        .await
        .map_err(|err| err.to_string())?;
    let attachment_rows = fetch_policy_attachments(db, tenant_id)
        .await
        .map_err(|err| err.to_string())?;

    build_effective_agent_policy(
        tenant_id,
        agent,
        active_policy.as_ref(),
        &membership_scope,
        attachment_rows,
    )
}

pub async fn preview_effective_policy_for_agent(
    db: &PgPool,
    tenant_id: Uuid,
    agent_id: &str,
    policy_yaml: &str,
    description: Option<&str>,
) -> Result<Option<EffectiveAgentPolicy>, String> {
    let candidate =
        preview_active_policy_candidate(db, tenant_id, policy_yaml, description).await?;
    preview_effective_policy_candidate_for_agent(db, tenant_id, agent_id, &candidate).await
}

pub async fn preview_effective_policy_candidate_for_agent(
    db: &PgPool,
    tenant_id: Uuid,
    agent_id: &str,
    candidate: &ActiveTenantPolicy,
) -> Result<Option<EffectiveAgentPolicy>, String> {
    let Some(agent) = fetch_policy_agent_context(db, tenant_id, agent_id).await? else {
        return Ok(None);
    };
    let membership_scope = fetch_principal_membership_scope(db, tenant_id, agent.principal_id)
        .await
        .map_err(|err| err.to_string())?;
    let attachment_rows = fetch_policy_attachments(db, tenant_id)
        .await
        .map_err(|err| err.to_string())?;

    build_effective_agent_policy(
        tenant_id,
        agent,
        Some(candidate),
        &membership_scope,
        attachment_rows,
    )
}

fn build_effective_agent_policy(
    tenant_id: Uuid,
    agent: PolicyAgentContext,
    active_policy: Option<&ActiveTenantPolicy>,
    membership_scope: &PrincipalMembershipScope,
    attachment_rows: Vec<PolicyAttachment>,
) -> Result<Option<EffectiveAgentPolicy>, String> {
    let mut compiled = match active_policy {
        Some(policy) => serde_yaml::from_str::<serde_yaml::Value>(&policy.policy_yaml)
            .map_err(|err| format!("active tenant policy is invalid YAML: {err}"))?,
        None => serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
    };

    let mut source_attachments = Vec::new();
    let mut applied_attachment_count = 0_i64;
    for attachment in attachment_rows {
        if !attachment.matches(tenant_id, agent.principal_id, membership_scope) {
            continue;
        }

        if let Some(policy_yaml) = attachment.resolved_policy_yaml()? {
            let overlay =
                serde_yaml::from_str::<serde_yaml::Value>(policy_yaml).map_err(|err| {
                    format!(
                        "policy attachment {} contains invalid YAML: {err}",
                        attachment.id
                    )
                })?;
            merge_yaml_value(&mut compiled, overlay);
        }

        source_attachments.push(EffectivePolicyAttachment {
            attachment_id: attachment.id,
            target_kind: attachment.target_kind.clone(),
            target_id: attachment.target_id.unwrap_or(tenant_id),
            priority: attachment.priority,
            policy_ref: attachment.policy_ref.clone(),
            checksum_sha256: attachment.checksum_sha256.clone(),
        });
        applied_attachment_count += 1;
    }

    if active_policy.is_none() && applied_attachment_count == 0 {
        return Ok(None);
    }

    let policy_epoch =
        active_policy.map(|policy| policy.version).unwrap_or(0) + applied_attachment_count;
    let policy_epoch_u64 = u64::try_from(policy_epoch)
        .map_err(|_| format!("effective policy epoch {policy_epoch} is invalid"))?;
    let compiled_policy_yaml = serialize_compiled_policy(&compiled)
        .map_err(|err| format!("failed to serialize effective policy YAML: {err}"))?;
    let policy_yaml = stamp_policy_epoch(&compiled_policy_yaml, policy_epoch_u64)?;
    let checksum_sha256 = checksum_sha256_hex(&policy_yaml);
    let applied_overlays = lifecycle_overlay_names(&agent.lifecycle_state);

    Ok(Some(EffectiveAgentPolicy {
        tenant_id,
        tenant_slug: agent.tenant_slug,
        agent_id: agent.agent_id,
        principal_id: agent.principal_id,
        lifecycle_state: agent.lifecycle_state,
        liveness_state: agent.liveness_state,
        policy_yaml,
        checksum_sha256,
        policy_epoch,
        source_attachments,
        applied_overlays,
    }))
}

fn stamp_policy_epoch(policy_yaml: &str, policy_epoch: u64) -> Result<String, String> {
    if policy_epoch == 0 {
        return Err("policy epoch must be greater than zero".to_string());
    }

    let mut value = serde_yaml::from_str::<serde_yaml::Value>(policy_yaml)
        .map_err(|err| format!("invalid policy YAML: {err}"))?;
    let serde_yaml::Value::Mapping(map) = &mut value else {
        return Err("policy YAML root must be a mapping to stamp policy epoch".to_string());
    };

    remove_policy_epoch_metadata(map);
    map.insert(
        serde_yaml::Value::String("policy_epoch".to_string()),
        serde_yaml::to_value(policy_epoch)
            .map_err(|err| format!("failed to serialize policy epoch: {err}"))?,
    );
    serde_yaml::to_string(&value).map_err(|err| format!("failed to serialize policy YAML: {err}"))
}

fn policy_yaml_content_matches_ignoring_epoch(left: &[u8], right: &[u8]) -> bool {
    let Some(left) = policy_yaml_without_epoch_metadata(left) else {
        return false;
    };
    let Some(right) = policy_yaml_without_epoch_metadata(right) else {
        return false;
    };
    left == right
}

fn policy_yaml_without_epoch_metadata(policy_yaml: &[u8]) -> Option<serde_yaml::Value> {
    let mut value: serde_yaml::Value = serde_yaml::from_slice(policy_yaml).ok()?;
    let serde_yaml::Value::Mapping(map) = &mut value else {
        return Some(value);
    };
    remove_policy_epoch_metadata(map);
    Some(value)
}

fn policy_epoch_from_yaml(policy_yaml: &[u8]) -> Option<u64> {
    let root: serde_yaml::Value = serde_yaml::from_slice(policy_yaml).ok()?;
    POLICY_SYNC_EPOCH_YAML_PATHS
        .iter()
        .filter_map(|path| yaml_u64_at_path(&root, path))
        .find(|epoch| *epoch > 0)
}

fn yaml_u64_at_path(value: &serde_yaml::Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    yaml_u64_value(current)
}

fn yaml_u64_value(value: &serde_yaml::Value) -> Option<u64> {
    match value {
        serde_yaml::Value::Number(value) => value.as_u64(),
        serde_yaml::Value::String(value) => value.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn remove_policy_epoch_metadata(map: &mut serde_yaml::Mapping) {
    for key in ["policy_epoch", "policyEpoch", "epoch"] {
        map.remove(serde_yaml::Value::String(key.to_string()));
    }
    for container in ["policy", "metadata", "bundle"] {
        let key = serde_yaml::Value::String(container.to_string());
        let mut empty_after_strip = false;
        if let Some(serde_yaml::Value::Mapping(child)) = map.get_mut(&key) {
            for epoch_key in ["policy_epoch", "policyEpoch", "epoch"] {
                child.remove(serde_yaml::Value::String(epoch_key.to_string()));
            }
            empty_after_strip = child.is_empty();
        }
        if empty_after_strip {
            map.remove(&key);
        }
    }
}

struct PolicyAgentContext {
    tenant_slug: String,
    agent_id: String,
    principal_id: Option<Uuid>,
    lifecycle_state: String,
    liveness_state: Option<String>,
}

struct PrincipalMembershipScope {
    swarm_ids: HashSet<Uuid>,
    project_ids: HashSet<Uuid>,
    capability_group_ids: HashSet<Uuid>,
}

struct PolicyAttachment {
    id: Uuid,
    target_kind: String,
    target_id: Option<Uuid>,
    priority: i32,
    policy_ref: Option<String>,
    policy_yaml: Option<String>,
    checksum_sha256: Option<String>,
}

async fn fetch_policy_agent_context(
    db: &PgPool,
    tenant_id: Uuid,
    agent_id: &str,
) -> Result<Option<PolicyAgentContext>, String> {
    let row = sqlx::query::query(
        r#"SELECT t.slug AS tenant_slug,
                  a.agent_id,
                  a.principal_id,
                  p.lifecycle_state,
                  p.liveness_state
           FROM agents AS a
           JOIN tenants AS t
             ON t.id = a.tenant_id
           LEFT JOIN principals AS p
             ON p.id = a.principal_id
           WHERE a.tenant_id = $1
             AND a.agent_id = $2"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .fetch_optional(db)
    .await
    .map_err(|err| err.to_string())?;

    row.map(|row| {
        let lifecycle_state = row
            .try_get::<Option<String>, _>("lifecycle_state")
            .map_err(|err| err.to_string())?
            .unwrap_or_else(|| "active".to_string());
        Ok(PolicyAgentContext {
            tenant_slug: row.try_get("tenant_slug").map_err(|err| err.to_string())?,
            agent_id: row.try_get("agent_id").map_err(|err| err.to_string())?,
            principal_id: row.try_get("principal_id").map_err(|err| err.to_string())?,
            lifecycle_state,
            liveness_state: row
                .try_get("liveness_state")
                .map_err(|err| err.to_string())?,
        })
    })
    .transpose()
}

async fn fetch_principal_membership_scope(
    db: &PgPool,
    tenant_id: Uuid,
    principal_id: Option<Uuid>,
) -> Result<PrincipalMembershipScope, sqlx::error::Error> {
    let Some(principal_id) = principal_id else {
        return Ok(PrincipalMembershipScope {
            swarm_ids: HashSet::new(),
            project_ids: HashSet::new(),
            capability_group_ids: HashSet::new(),
        });
    };

    let memberships = sqlx::query::query(
        r#"SELECT target_kind, target_id
           FROM principal_memberships
           WHERE tenant_id = $1
             AND principal_id = $2"#,
    )
    .bind(tenant_id)
    .bind(principal_id)
    .fetch_all(db)
    .await?;

    let mut scope = PrincipalMembershipScope {
        swarm_ids: HashSet::new(),
        project_ids: HashSet::new(),
        capability_group_ids: HashSet::new(),
    };
    for membership in memberships {
        let target_kind: String = membership.try_get("target_kind")?;
        let target_id: Uuid = membership.try_get("target_id")?;
        match target_kind.as_str() {
            "swarm" => {
                scope.swarm_ids.insert(target_id);
            }
            "project" => {
                scope.project_ids.insert(target_id);
            }
            "capability_group" => {
                scope.capability_group_ids.insert(target_id);
            }
            _ => {}
        }
    }
    Ok(scope)
}

async fn fetch_policy_attachments(
    db: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<PolicyAttachment>, sqlx::error::Error> {
    let rows = sqlx::query::query(
        r#"SELECT id,
                  target_kind,
                  target_id,
                  priority,
                  policy_ref,
                  policy_yaml,
                  checksum_sha256
           FROM policy_attachments
           WHERE tenant_id = $1
           ORDER BY CASE target_kind
                        WHEN 'tenant' THEN 1
                        WHEN 'swarm' THEN 2
                        WHEN 'project' THEN 3
                        WHEN 'capability_group' THEN 4
                        WHEN 'principal' THEN 5
                        ELSE 6
                    END ASC,
                    priority ASC,
                    created_at ASC,
                    id ASC"#,
    )
    .bind(tenant_id)
    .fetch_all(db)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(PolicyAttachment {
                id: row.try_get("id")?,
                target_kind: row.try_get("target_kind")?,
                target_id: row.try_get("target_id")?,
                priority: row.try_get("priority")?,
                policy_ref: row.try_get("policy_ref")?,
                policy_yaml: row.try_get("policy_yaml")?,
                checksum_sha256: row.try_get("checksum_sha256")?,
            })
        })
        .collect()
}

impl PolicyAttachment {
    fn matches(
        &self,
        tenant_id: Uuid,
        principal_id: Option<Uuid>,
        scope: &PrincipalMembershipScope,
    ) -> bool {
        match self.target_kind.as_str() {
            "tenant" => self.target_id.is_none(),
            "swarm" => self
                .target_id
                .is_some_and(|id| scope.swarm_ids.contains(&id)),
            "project" => self
                .target_id
                .is_some_and(|id| scope.project_ids.contains(&id)),
            "capability_group" => self
                .target_id
                .is_some_and(|id| scope.capability_group_ids.contains(&id)),
            "principal" => principal_id.is_some_and(|id| self.target_id == Some(id)),
            _ => self.target_id == Some(tenant_id) && self.target_kind == "tenant",
        }
    }

    fn resolved_policy_yaml(&self) -> Result<Option<&str>, String> {
        match (self.policy_yaml.as_deref(), self.policy_ref.as_deref()) {
            (Some(policy_yaml), _) => Ok(Some(policy_yaml)),
            (None, Some(policy_ref)) => Err(format!(
                "policy attachment {} references unresolved policy_ref `{policy_ref}`",
                self.id
            )),
            (None, None) => Ok(None),
        }
    }
}

fn serialize_compiled_policy(value: &serde_yaml::Value) -> Result<String, serde_yaml::Error> {
    match value {
        serde_yaml::Value::Mapping(map) if map.is_empty() => Ok(String::new()),
        serde_yaml::Value::Null => Ok(String::new()),
        _ => serde_yaml::to_string(value),
    }
}

fn merge_yaml_value(base: &mut serde_yaml::Value, overlay: serde_yaml::Value) {
    match (base, overlay) {
        (serde_yaml::Value::Mapping(base_map), serde_yaml::Value::Mapping(overlay_map)) => {
            for (key, value) in overlay_map {
                if value.is_null() {
                    base_map.remove(&key);
                    continue;
                }

                if let Some(existing) = base_map.get_mut(&key) {
                    merge_yaml_value(existing, value);
                } else {
                    base_map.insert(key, value);
                }
            }
        }
        (base_slot, replacement) => {
            *base_slot = replacement;
        }
    }
}

fn lifecycle_overlay_names(lifecycle_state: &str) -> Vec<String> {
    match lifecycle_state {
        "restricted" => vec!["restricted".to_string()],
        "observe_only" => vec!["observe_only".to_string()],
        "quarantined" => vec!["quarantined".to_string()],
        "revoked" => vec!["revoked".to_string()],
        _ => Vec::new(),
    }
}

fn row_to_active_policy(
    row: sqlx_postgres::PgRow,
) -> Result<ActiveTenantPolicy, sqlx::error::Error> {
    Ok(ActiveTenantPolicy {
        tenant_id: row.try_get("tenant_id")?,
        tenant_slug: row.try_get("tenant_slug")?,
        policy_yaml: row.try_get("policy_yaml")?,
        checksum_sha256: row.try_get("checksum_sha256")?,
        description: row.try_get("description")?,
        version: row.try_get("version")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn fetch_tenant_slug_by_id(
    db: &PgPool,
    tenant_id: Uuid,
) -> Result<Option<String>, sqlx::error::Error> {
    let row = sqlx::query::query("SELECT slug FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(db)
        .await?;

    row.map(|row| row.try_get("slug")).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_subject_uses_tenant_prefix_contract() {
        assert_eq!(
            policy_update_subject("acme"),
            "tenant-acme.clawdstrike.policy.update"
        );
    }

    #[test]
    fn policy_sync_bucket_matches_agent_contract() {
        assert_eq!(
            policy_sync_bucket("tenant-acme.clawdstrike", "agent-123"),
            "tenant-acme-clawdstrike-policy-sync-agent-123"
        );
    }

    #[test]
    fn policy_sync_key_is_stable() {
        assert_eq!(POLICY_SYNC_KEY, "policy.yaml");
    }

    #[test]
    fn policy_checksum_is_stable_hex_sha256() {
        let checksum = policy_yaml_checksum_sha256("version: 1\n");
        assert_eq!(checksum.len(), 64);
        assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn policy_document_validation_requires_mapping_root() {
        validate_policy_document("policy:\n  mode: observe\n").expect("mapping policy is valid");

        let err =
            validate_policy_document("- rule-a\n- rule-b\n").expect_err("sequence root must fail");
        assert_eq!(err, "policy YAML root must be a mapping");
    }

    #[test]
    fn distribution_policy_yaml_stamps_database_version_epoch() {
        let policy = ActiveTenantPolicy {
            tenant_id: Uuid::new_v4(),
            tenant_slug: "acme".to_string(),
            policy_yaml: r#"
version: "1.0.0"
policyEpoch: 999
metadata:
  policy_epoch: 1000
bundle:
  epoch: 1001
rules: []
"#
            .to_string(),
            checksum_sha256: checksum_sha256_hex("policy"),
            description: None,
            version: 42,
            updated_at: Utc::now(),
        };

        let payload = distribution_policy_yaml(&policy).expect("distribution payload");
        let value: serde_yaml::Value = serde_yaml::from_str(&payload).expect("payload YAML");

        assert_eq!(
            value
                .get("policy_epoch")
                .and_then(serde_yaml::Value::as_u64),
            Some(42)
        );
        assert!(value.get("policyEpoch").is_none());
        assert!(value
            .get("metadata")
            .and_then(|metadata| metadata.get("policy_epoch"))
            .is_none());
        assert!(value
            .get("bundle")
            .and_then(|bundle| bundle.get("epoch"))
            .is_none());
    }

    #[test]
    fn distribution_policy_yaml_rejects_non_mapping_policy_root() {
        let policy = ActiveTenantPolicy {
            tenant_id: Uuid::new_v4(),
            tenant_slug: "acme".to_string(),
            policy_yaml: "- rule-a\n- rule-b\n".to_string(),
            checksum_sha256: checksum_sha256_hex("policy"),
            description: None,
            version: 1,
            updated_at: Utc::now(),
        };

        let err = distribution_policy_yaml(&policy).expect_err("non-mapping policy root");
        assert!(err.contains("root must be a mapping"));
    }

    #[test]
    fn effective_agent_policy_merges_matching_overlays_and_stamps_epoch() {
        let tenant_id = Uuid::new_v4();
        let principal_id = Uuid::new_v4();
        let swarm_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let capability_group_id = Uuid::new_v4();
        let unrelated_project_id = Uuid::new_v4();
        let active_policy = ActiveTenantPolicy {
            tenant_id,
            tenant_slug: "acme".to_string(),
            policy_yaml: "policy:\n  mode: tenant-base\n  keep: true\npolicy_epoch: 999\n"
                .to_string(),
            checksum_sha256: checksum_sha256_hex("policy"),
            description: None,
            version: 7,
            updated_at: Utc::now(),
        };
        let agent = PolicyAgentContext {
            tenant_slug: "acme".to_string(),
            agent_id: "agent-123".to_string(),
            principal_id: Some(principal_id),
            lifecycle_state: "restricted".to_string(),
            liveness_state: Some("active".to_string()),
        };
        let scope = PrincipalMembershipScope {
            swarm_ids: HashSet::from([swarm_id]),
            project_ids: HashSet::from([project_id]),
            capability_group_ids: HashSet::from([capability_group_id]),
        };
        let attachments = vec![
            test_attachment("tenant", None, 10, "policy:\n  mode: tenant-overlay\n"),
            test_attachment("swarm", Some(swarm_id), 20, "policy:\n  mode: swarm\n"),
            test_attachment("project", Some(project_id), 30, "policy:\n  region: prod\n"),
            test_attachment(
                "capability_group",
                Some(capability_group_id),
                40,
                "policy:\n  capability: responder\n",
            ),
            test_attachment(
                "project",
                Some(unrelated_project_id),
                45,
                "policy:\n  region: dev\n",
            ),
            test_attachment(
                "principal",
                Some(principal_id),
                50,
                "policy:\n  keep: null\n  final: true\npolicyEpoch: 1000\n",
            ),
        ];

        let resolved = build_effective_agent_policy(
            tenant_id,
            agent,
            Some(&active_policy),
            &scope,
            attachments,
        )
        .expect("effective policy should resolve")
        .expect("effective policy should exist");
        let value: serde_yaml::Value =
            serde_yaml::from_str(&resolved.policy_yaml).expect("effective policy YAML");

        assert_eq!(resolved.policy_epoch, 12);
        assert_eq!(resolved.source_attachments.len(), 5);
        assert_eq!(resolved.applied_overlays, vec!["restricted"]);
        assert_eq!(
            value
                .get("policy_epoch")
                .and_then(serde_yaml::Value::as_u64),
            Some(12)
        );
        assert_eq!(
            value
                .get("policy")
                .and_then(|policy| policy.get("mode"))
                .and_then(serde_yaml::Value::as_str),
            Some("swarm")
        );
        assert_eq!(
            value
                .get("policy")
                .and_then(|policy| policy.get("region"))
                .and_then(serde_yaml::Value::as_str),
            Some("prod")
        );
        assert_eq!(
            value
                .get("policy")
                .and_then(|policy| policy.get("capability"))
                .and_then(serde_yaml::Value::as_str),
            Some("responder")
        );
        assert_eq!(
            value
                .get("policy")
                .and_then(|policy| policy.get("final"))
                .and_then(serde_yaml::Value::as_bool),
            Some(true)
        );
        assert!(value
            .get("policy")
            .and_then(|policy| policy.get("keep"))
            .is_none());
        assert!(value.get("policyEpoch").is_none());
    }

    #[test]
    fn effective_policy_publish_epoch_advances_same_epoch_content_change() {
        let existing = "policy:
  mode: old
policy_epoch: 12
";
        let candidate = "policy:
  mode: new
policy_epoch: 12
";

        let restamped = policy_yaml_with_epoch_after_existing(candidate, existing.as_bytes())
            .expect("restamped policy");
        let value: serde_yaml::Value = serde_yaml::from_str(&restamped).expect("policy YAML");

        assert_eq!(
            value
                .get("policy_epoch")
                .and_then(serde_yaml::Value::as_u64),
            Some(13)
        );
        assert_eq!(
            value
                .get("policy")
                .and_then(|policy| policy.get("mode"))
                .and_then(serde_yaml::Value::as_str),
            Some("new")
        );
    }

    #[test]
    fn effective_policy_publish_epoch_ignores_epoch_only_drift() {
        let existing = "policy:
  mode: new
policy_epoch: 13
";
        let candidate = "policy:
  mode: new
policy_epoch: 12
";

        assert!(policy_yaml_content_matches_ignoring_epoch(
            candidate.as_bytes(),
            existing.as_bytes()
        ));
        assert!(
            !candidate_policy_epoch_advances_existing(candidate, existing.as_bytes())
                .expect("epoch comparison")
        );
    }

    #[test]
    fn effective_policy_publish_epoch_writes_higher_epoch_same_content() {
        let existing = "policy:
  mode: new
policy_epoch: 13
";
        let candidate = "policy:
  mode: new
policy_epoch: 14
";

        assert!(policy_yaml_content_matches_ignoring_epoch(
            candidate.as_bytes(),
            existing.as_bytes()
        ));
        assert!(
            candidate_policy_epoch_advances_existing(candidate, existing.as_bytes())
                .expect("epoch comparison")
        );
    }

    #[test]
    fn effective_policy_publish_epoch_keeps_higher_candidate_epoch() {
        let existing = "policy:
  mode: old
policy_epoch: 12
";
        let candidate = "policy:
  mode: new
policy_epoch: 20
";

        let restamped = policy_yaml_with_epoch_after_existing(candidate, existing.as_bytes())
            .expect("restamped policy");
        let value: serde_yaml::Value = serde_yaml::from_str(&restamped).expect("policy YAML");

        assert_eq!(
            value
                .get("policy_epoch")
                .and_then(serde_yaml::Value::as_u64),
            Some(20)
        );
    }

    fn test_attachment(
        target_kind: &str,
        target_id: Option<Uuid>,
        priority: i32,
        policy_yaml: &str,
    ) -> PolicyAttachment {
        PolicyAttachment {
            id: Uuid::new_v4(),
            target_kind: target_kind.to_string(),
            target_id,
            priority,
            policy_ref: None,
            policy_yaml: Some(policy_yaml.to_string()),
            checksum_sha256: Some(checksum_sha256_hex(policy_yaml)),
        }
    }
}
