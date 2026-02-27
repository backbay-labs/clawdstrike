#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

fn migration_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("migrations")
        .join(name)
}

#[test]
fn adaptive_sdr_migration_adds_required_schema() {
    let sql = fs::read_to_string(migration_path("002_adaptive_sdr_schema.sql"))
        .expect("failed to read 002 migration");

    assert!(
        sql.contains("ADD COLUMN IF NOT EXISTS enrollment_token"),
        "002 migration must add tenants.enrollment_token"
    );
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS approvals"),
        "002 migration must create approvals table"
    );
    assert!(
        sql.contains("status IN ('active', 'inactive', 'revoked', 'stale', 'dead')"),
        "002 migration must expand agents.status values"
    );
}

#[test]
fn adaptive_sdr_followup_migration_hardens_token_and_approval_flow() {
    let sql = fs::read_to_string(migration_path(
        "003_adaptive_sdr_token_and_approval_flow.sql",
    ))
    .expect("failed to read 003 migration");

    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS tenant_enrollment_tokens"),
        "003 migration must create tenant_enrollment_tokens"
    );
    assert!(
        sql.contains("DROP COLUMN IF EXISTS enrollment_token"),
        "003 migration must remove legacy tenants.enrollment_token"
    );
    assert!(
        sql.contains("ADD COLUMN IF NOT EXISTS request_id"),
        "003 migration must add approvals.request_id"
    );
    assert!(
        sql.contains("idx_approvals_tenant_request_id"),
        "003 migration must add unique (tenant_id, request_id) index"
    );
}

#[test]
fn init_and_adaptive_migrations_are_ordered() {
    let init_sql =
        fs::read_to_string(migration_path("001_init.sql")).expect("failed to read 001 migration");
    let adaptive_sql = fs::read_to_string(migration_path("002_adaptive_sdr_schema.sql"))
        .expect("failed to read 002 migration");
    let followup_sql = fs::read_to_string(migration_path(
        "003_adaptive_sdr_token_and_approval_flow.sql",
    ))
    .expect("failed to read 003 migration");
    let active_policy_sql =
        fs::read_to_string(migration_path("004_adaptive_sdr_active_policy.sql"))
            .expect("failed to read 004 migration");
    let approval_outbox_sql =
        fs::read_to_string(migration_path("005_adaptive_sdr_approval_outbox.sql"))
            .expect("failed to read 005 migration");

    assert!(
        init_sql.contains("CREATE TABLE tenants"),
        "001 must define tenants table before adaptive migration extends it"
    );
    assert!(
        init_sql.contains("CREATE TABLE agents"),
        "001 must define agents table before adaptive migration alters constraints"
    );
    assert!(
        adaptive_sql.contains("ALTER TABLE agents"),
        "002 must alter agents table after initial creation"
    );
    assert!(
        followup_sql.contains("tenant_enrollment_tokens"),
        "003 must apply after 001/002 and extend enrollment + approvals flow"
    );
    assert!(
        active_policy_sql.contains("CREATE TABLE IF NOT EXISTS tenant_active_policies"),
        "004 must define tenant-level active policy state"
    );
    assert!(
        active_policy_sql.contains("version BIGINT"),
        "004 must include versioned active policy tracking"
    );
    assert!(
        approval_outbox_sql.contains("CREATE TABLE IF NOT EXISTS approval_resolution_outbox"),
        "005 must define durable approval resolution outbox"
    );
    assert!(
        approval_outbox_sql.contains("CHECK (status IN ('pending', 'sent'))"),
        "005 must constrain outbox statuses"
    );
}
