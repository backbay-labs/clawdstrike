//! Shared policy distribution utilities for cloud-side deploy and backfill flows.
//!
//! This module provides:
//! - Tenant-level active policy persistence (`tenant_active_policies`)
//! - Canonical policy sync bucket/key naming
//! - Agent KV writes/backfill reconciliation

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgPool;
use crate::services::tenant_provisioner::tenant_subject_prefix;

pub const POLICY_SYNC_KEY: &str = "policy.yaml";

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

pub async fn upsert_active_policy(
    db: &PgPool,
    tenant_id: Uuid,
    policy_yaml: &str,
    description: Option<&str>,
) -> Result<ActiveTenantPolicy, sqlx::error::Error> {
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
    .fetch_one(db)
    .await?;

    row_to_active_policy(row)
}

pub async fn fetch_active_policy_by_tenant_id(
    db: &PgPool,
    tenant_id: Uuid,
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
           WHERE p.tenant_id = $1"#,
    )
    .bind(tenant_id)
    .fetch_optional(db)
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

pub async fn put_policy_for_agent(
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
    let js = async_nats::jetstream::new(nats.clone());
    let bucket = policy_sync_bucket(&tenant_subject_prefix(&policy.tenant_slug), agent_id);
    let store = spine::nats_transport::ensure_kv(&js, &bucket, 1)
        .await
        .map_err(|err| err.to_string())?;

    let expected_bytes = policy.policy_yaml.as_bytes();
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
        let checksum = checksum_sha256_hex("version: 1\n");
        assert_eq!(checksum.len(), 64);
        assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
