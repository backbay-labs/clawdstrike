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
fn init_and_adaptive_migrations_are_ordered() {
    let init_sql =
        fs::read_to_string(migration_path("001_init.sql")).expect("failed to read 001 migration");
    let adaptive_sql = fs::read_to_string(migration_path("002_adaptive_sdr_schema.sql"))
        .expect("failed to read 002 migration");

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
}
