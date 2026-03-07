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
fn fleet_directory_migrations_define_core_tables_and_backfills() {
    let core_sql = fs::read_to_string(migration_path("006_fleet_directory_core.sql"))
        .expect("failed to read 006 migration");
    let backfill_sql = fs::read_to_string(migration_path("007_fleet_directory_backfill.sql"))
        .expect("failed to read 007 migration");
    let attachment_sql =
        fs::read_to_string(migration_path("008_fleet_directory_policy_attachments.sql"))
            .expect("failed to read 008 migration");
    let references_sql = fs::read_to_string(migration_path("009_fleet_directory_references.sql"))
        .expect("failed to read 009 migration");

    assert!(
        core_sql.contains("CREATE TABLE IF NOT EXISTS principals"),
        "006 migration must create principals table"
    );
    assert!(
        core_sql.contains("CREATE TABLE IF NOT EXISTS principal_memberships"),
        "006 migration must create principal membership table"
    );
    assert!(
        core_sql.contains("projects_tenant_swarm_fk")
            && core_sql.contains("REFERENCES swarms(tenant_id, id)"),
        "006 migration must scope project-to-swarm links by tenant"
    );
    assert!(
        core_sql.contains("grants_issuer_principal_tenant_fk")
            && core_sql.contains("grants_subject_principal_tenant_fk")
            && core_sql.contains("REFERENCES principals(tenant_id, id)"),
        "006 migration must scope grant principal links by tenant"
    );
    assert!(
        core_sql.contains("grants_source_approval_tenant_fk")
            && core_sql.contains("REFERENCES approvals(tenant_id, id)"),
        "006 migration must scope grant approval provenance by tenant"
    );
    assert!(
        core_sql.contains("CREATE TABLE IF NOT EXISTS delegation_edges"),
        "006 migration must create delegation edge table"
    );
    assert!(
        backfill_sql.contains("ADD COLUMN IF NOT EXISTS principal_id"),
        "007 migration must add agents.principal_id"
    );
    assert!(
        backfill_sql.contains("agents_principal_tenant_fk"),
        "007 migration must enforce tenant-scoped agent principal links"
    );
    assert!(
        backfill_sql.contains("REFERENCES principals(tenant_id, id)"),
        "007 migration must reference principals by tenant_id + id"
    );
    assert!(
        backfill_sql.contains("INSERT INTO principals"),
        "007 migration must backfill principals"
    );
    assert!(
        attachment_sql.contains("CREATE TABLE IF NOT EXISTS policy_attachments"),
        "008 migration must create policy_attachments"
    );
    assert!(
        attachment_sql.contains("policy_ref TEXT"),
        "008 migration must persist optional policy references"
    );
    assert!(
        attachment_sql.contains("policy_attachments_payload_check"),
        "008 migration must validate attachment payload presence"
    );
    assert!(
        references_sql.contains("ALTER TABLE approvals"),
        "009 migration must extend approvals"
    );
    assert!(
        references_sql.contains("approvals_tenant_id_id_key"),
        "009 migration must add the approvals tenant composite uniqueness needed by downstream FKs"
    );
    assert!(
        references_sql.contains("approvals_principal_tenant_fk"),
        "009 migration must enforce tenant-scoped approval principal links"
    );
    assert!(
        references_sql.contains("idx_approvals_tenant_principal"),
        "009 migration must index approval principal lookups"
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
    let directory_core_sql = fs::read_to_string(migration_path("006_fleet_directory_core.sql"))
        .expect("failed to read 006 migration");
    let directory_backfill_sql =
        fs::read_to_string(migration_path("007_fleet_directory_backfill.sql"))
            .expect("failed to read 007 migration");
    let directory_attachments_sql =
        fs::read_to_string(migration_path("008_fleet_directory_policy_attachments.sql"))
            .expect("failed to read 008 migration");
    let directory_references_sql =
        fs::read_to_string(migration_path("009_fleet_directory_references.sql"))
            .expect("failed to read 009 migration");
    let detection_core_sql = fs::read_to_string(migration_path("010_detection_core.sql"))
        .expect("failed to read 010 migration");
    let hunt_backend_sql = fs::read_to_string(migration_path("012_hunt_backend.sql"))
        .expect("failed to read 012 migration");

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
    assert!(
        directory_core_sql.contains("CREATE TABLE IF NOT EXISTS principals"),
        "006 must establish directory tables before compatibility links"
    );
    assert!(
        directory_backfill_sql.contains("ALTER TABLE agents"),
        "007 must extend agents after core directory schema exists"
    );
    assert!(
        directory_attachments_sql.contains("CREATE TABLE IF NOT EXISTS policy_attachments"),
        "008 must land attachment storage after principal schema exists"
    );
    assert!(
        directory_references_sql.contains("ALTER TABLE approvals"),
        "009 must add principal references after principal backfill exists"
    );
    assert!(
        detection_core_sql.contains("CREATE TABLE detection_rules")
            || detection_core_sql.contains("CREATE TABLE IF NOT EXISTS detection_rules"),
        "010 must define detection rule storage before downstream detection features"
    );
    assert!(
        hunt_backend_sql.contains("CREATE TABLE hunt_envelopes")
            || hunt_backend_sql.contains("CREATE TABLE IF NOT EXISTS hunt_envelopes"),
        "012 must define hunt envelope storage after the detection and response base exists"
    );
}

#[test]
fn detection_core_migration_adds_rule_finding_and_pack_schema() {
    let sql = fs::read_to_string(migration_path("010_detection_core.sql"))
        .expect("failed to read 010 migration");

    assert!(
        sql.contains("CREATE TABLE detection_rules")
            || sql.contains("CREATE TABLE IF NOT EXISTS detection_rules"),
        "010 migration must create detection_rules"
    );
    assert!(
        sql.contains("CREATE TABLE detection_findings")
            || sql.contains("CREATE TABLE IF NOT EXISTS detection_findings"),
        "010 migration must create detection_findings"
    );
    assert!(
        sql.contains("CREATE TABLE detection_suppressions")
            || sql.contains("CREATE TABLE IF NOT EXISTS detection_suppressions"),
        "010 migration must create detection_suppressions"
    );
    assert!(
        sql.contains("CREATE TABLE installed_detection_packs")
            || sql.contains("CREATE TABLE IF NOT EXISTS installed_detection_packs"),
        "010 migration must create installed_detection_packs"
    );
    assert!(
        sql.contains("source_format IN (")
            && sql.contains("'native_correlation'")
            && sql.contains("'sigma'")
            && sql.contains("'yara'"),
        "010 migration must constrain supported detection source formats"
    );
}

#[test]
fn response_action_migration_adds_execution_ledger_schema() {
    let sql = fs::read_to_string(migration_path(
        "011_response_actions_and_execution_ledger.sql",
    ))
    .expect("failed to read 011 migration");

    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS response_actions"),
        "011 migration must create response_actions"
    );
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS response_action_deliveries"),
        "011 migration must create response_action_deliveries"
    );
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS response_action_acks"),
        "011 migration must create response_action_acks"
    );
    assert!(
        sql.contains("case_id UUID"),
        "011 migration must persist case_id as a UUID"
    );
    assert!(
        sql.contains("delivery_id UUID NOT NULL"),
        "011 migration must link acknowledgements to a concrete delivery"
    );
    assert!(
        sql.contains("CONSTRAINT response_actions_tenant_id_id_key")
            && sql.contains("UNIQUE (tenant_id, id)"),
        "011 migration must add a tenant-scoped unique key for response actions"
    );
    assert!(
        sql.contains("FOREIGN KEY (tenant_id, action_id)\n        REFERENCES response_actions(tenant_id, id)"),
        "011 migration must enforce tenant-scoped delivery/action integrity"
    );
    assert!(
        sql.contains(
            "FOREIGN KEY (tenant_id, delivery_id, action_id, target_kind, target_id)\n        REFERENCES response_action_deliveries(tenant_id, id, action_id, target_kind, target_id)"
        ),
        "011 migration must bind acknowledgements to the same delivery identity they reference"
    );
    assert!(
        !sql.contains("REFERENCES detection_findings(tenant_id, id)\n        ON DELETE SET NULL"),
        "011 migration must keep tenant-scoped provenance FKs immutable"
    );
    assert!(
        !sql.contains("REFERENCES approvals(tenant_id, id)\n        ON DELETE SET NULL"),
        "011 migration must keep tenant-scoped approval provenance FKs immutable"
    );
    assert!(
        sql.contains("UNIQUE (delivery_id)"),
        "011 migration must prevent multiple acknowledgements per delivery"
    );
    assert!(
        sql.contains("status IN (")
            && sql.contains("'queued'")
            && sql.contains("'acknowledged'")
            && sql.contains("'cancelled'"),
        "011 migration must constrain response action statuses"
    );
}

#[test]
fn hunt_backend_migration_adds_event_store_and_saved_hunts() {
    let sql = fs::read_to_string(migration_path("012_hunt_backend.sql"))
        .expect("failed to read 012 migration");

    assert!(
        sql.contains("CREATE TABLE hunt_envelopes")
            || sql.contains("CREATE TABLE IF NOT EXISTS hunt_envelopes"),
        "012 migration must create hunt_envelopes"
    );
    assert!(
        sql.contains("CREATE TABLE hunt_events")
            || sql.contains("CREATE TABLE IF NOT EXISTS hunt_events"),
        "012 migration must create hunt_events"
    );
    assert!(
        sql.contains("CREATE TABLE saved_hunts")
            || sql.contains("CREATE TABLE IF NOT EXISTS saved_hunts"),
        "012 migration must create saved_hunts"
    );
    assert!(
        sql.contains("CREATE TABLE hunt_jobs")
            || sql.contains("CREATE TABLE IF NOT EXISTS hunt_jobs"),
        "012 migration must create hunt_jobs"
    );
    assert!(
        sql.contains("CREATE INDEX idx_hunt_events_detection_ids")
            || sql.contains("CREATE INDEX IF NOT EXISTS idx_hunt_events_detection_ids"),
        "012 migration must index detection_ids for investigation joins"
    );
    assert!(
        sql.contains("hunt_envelopes_tenant_id_id_key")
            && sql.contains("REFERENCES hunt_envelopes(tenant_id, id)"),
        "012 migration must keep hunt event -> envelope links tenant-scoped"
    );
}

#[test]
fn case_evidence_migration_adds_case_bundle_schema() {
    let sql = fs::read_to_string(migration_path("013_case_evidence_bundles.sql"))
        .expect("failed to read 013 migration");

    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS fleet_cases"),
        "013 migration must create fleet_cases"
    );
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS fleet_case_artifacts"),
        "013 migration must create fleet_case_artifacts"
    );
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS fleet_case_events"),
        "013 migration must create fleet_case_events"
    );
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS fleet_evidence_bundles"),
        "013 migration must create fleet_evidence_bundles"
    );
    assert!(
        sql.contains("status IN ('processing', 'completed', 'failed', 'expired')"),
        "013 migration must constrain fleet_evidence_bundles.status"
    );
    assert!(
        sql.contains("UNIQUE (case_id, artifact_kind, artifact_id)"),
        "013 migration must deduplicate case artifact references"
    );
    assert!(
        sql.contains("fleet_cases_tenant_id_id_key")
            && sql.contains("REFERENCES fleet_cases(tenant_id, id)"),
        "013 migration must keep case child tables tenant-scoped"
    );
}

#[test]
fn delegation_graph_migration_adds_grant_ledger_and_graph_tables() {
    let sql = fs::read_to_string(migration_path("014_grants_delegation_graph.sql"))
        .expect("failed to read 014 migration");

    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS fleet_grants"),
        "014 migration must define the durable fleet grant ledger"
    );
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS delegation_graph_nodes"),
        "014 migration must define graph nodes"
    );
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS delegation_graph_edges"),
        "014 migration must define graph edges"
    );
    assert!(
        sql.contains("fleet_grants_parent_tenant_fk")
            && sql.contains("REFERENCES fleet_grants(tenant_id, id)"),
        "014 migration must keep parent grant lineage tenant-scoped"
    );
}

#[test]
fn response_action_case_link_migration_adds_case_fk() {
    let sql = fs::read_to_string(migration_path("015_response_action_case_links.sql"))
        .expect("failed to read 015 migration");

    assert!(
        sql.contains("response_actions_case_tenant_fk"),
        "015 migration must add the response action -> case tenant-scoped FK"
    );
    assert!(
        sql.contains("REFERENCES fleet_cases(tenant_id, id)"),
        "015 migration must reference fleet_cases by tenant_id + id"
    );
    assert!(
        !sql.contains("ON DELETE SET NULL"),
        "015 migration must not rely on composite ON DELETE SET NULL"
    );
}
