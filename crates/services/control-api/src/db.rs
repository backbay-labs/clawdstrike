use sqlx::transaction::Transaction;
use sqlx_postgres::{PgPoolOptions, Postgres};

/// PostgreSQL connection pool type alias.
pub type PgPool = sqlx::pool::Pool<Postgres>;
pub type PgRow = sqlx_postgres::PgRow;

struct EmbeddedMigration {
    name: &'static str,
    sql: &'static str,
}

const EMBEDDED_MIGRATIONS: &[EmbeddedMigration] = &[
    EmbeddedMigration {
        name: "001_init.sql",
        sql: include_str!("../migrations/001_init.sql"),
    },
    EmbeddedMigration {
        name: "002_adaptive_sdr_schema.sql",
        sql: include_str!("../migrations/002_adaptive_sdr_schema.sql"),
    },
    EmbeddedMigration {
        name: "003_adaptive_sdr_token_and_approval_flow.sql",
        sql: include_str!("../migrations/003_adaptive_sdr_token_and_approval_flow.sql"),
    },
    EmbeddedMigration {
        name: "004_adaptive_sdr_active_policy.sql",
        sql: include_str!("../migrations/004_adaptive_sdr_active_policy.sql"),
    },
    EmbeddedMigration {
        name: "005_adaptive_sdr_approval_outbox.sql",
        sql: include_str!("../migrations/005_adaptive_sdr_approval_outbox.sql"),
    },
    EmbeddedMigration {
        name: "006_fleet_directory_core.sql",
        sql: include_str!("../migrations/006_fleet_directory_core.sql"),
    },
    EmbeddedMigration {
        name: "007_fleet_directory_backfill.sql",
        sql: include_str!("../migrations/007_fleet_directory_backfill.sql"),
    },
    EmbeddedMigration {
        name: "008_fleet_directory_policy_attachments.sql",
        sql: include_str!("../migrations/008_fleet_directory_policy_attachments.sql"),
    },
    EmbeddedMigration {
        name: "009_fleet_directory_references.sql",
        sql: include_str!("../migrations/009_fleet_directory_references.sql"),
    },
    EmbeddedMigration {
        name: "010_detection_core.sql",
        sql: include_str!("../migrations/010_detection_core.sql"),
    },
    EmbeddedMigration {
        name: "011_response_actions_and_execution_ledger.sql",
        sql: include_str!("../migrations/011_response_actions_and_execution_ledger.sql"),
    },
    EmbeddedMigration {
        name: "012_hunt_backend.sql",
        sql: include_str!("../migrations/012_hunt_backend.sql"),
    },
    EmbeddedMigration {
        name: "013_case_evidence_bundles.sql",
        sql: include_str!("../migrations/013_case_evidence_bundles.sql"),
    },
    EmbeddedMigration {
        name: "014_grants_delegation_graph.sql",
        sql: include_str!("../migrations/014_grants_delegation_graph.sql"),
    },
    EmbeddedMigration {
        name: "015_response_action_case_links.sql",
        sql: include_str!("../migrations/015_response_action_case_links.sql"),
    },
];

const MIGRATION_LOCK_KEY: i64 = 0x4353_4D49_4752;

async fn table_exists(
    tx: &mut Transaction<'_, Postgres>,
    table_name: &str,
) -> Result<bool, sqlx::error::Error> {
    sqlx::query_scalar::query_scalar::<_, bool>(
        r#"SELECT EXISTS (
               SELECT 1
               FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = $1
           )"#,
    )
    .bind(table_name)
    .fetch_one(&mut **tx)
    .await
}

async fn column_exists(
    tx: &mut Transaction<'_, Postgres>,
    table_name: &str,
    column_name: &str,
) -> Result<bool, sqlx::error::Error> {
    sqlx::query_scalar::query_scalar::<_, bool>(
        r#"SELECT EXISTS (
               SELECT 1
               FROM information_schema.columns
               WHERE table_schema = 'public'
                 AND table_name = $1
                 AND column_name = $2
           )"#,
    )
    .bind(table_name)
    .bind(column_name)
    .fetch_one(&mut **tx)
    .await
}

async fn insert_migration_marker(
    tx: &mut Transaction<'_, Postgres>,
    name: &'static str,
) -> Result<(), sqlx::error::Error> {
    sqlx::query::query("INSERT INTO schema_migrations (name) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(name)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn backfill_legacy_migration_markers(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<(), sqlx::error::Error> {
    let has_markers = sqlx::query_scalar::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM schema_migrations LIMIT 1)",
    )
    .fetch_one(&mut **tx)
    .await?;
    if has_markers {
        return Ok(());
    }

    let core_tables_exist = {
        let mut all_exist = true;
        for table in [
            "tenants",
            "users",
            "api_keys",
            "agents",
            "alert_configs",
            "usage_events",
        ] {
            all_exist &= table_exists(tx, table).await?;
        }
        all_exist
    };
    if !core_tables_exist {
        return Ok(());
    }

    insert_migration_marker(tx, "001_init.sql").await?;

    let approvals_exists = table_exists(tx, "approvals").await?;
    if approvals_exists {
        insert_migration_marker(tx, "002_adaptive_sdr_schema.sql").await?;
    }

    let tenant_enrollment_tokens_exists = table_exists(tx, "tenant_enrollment_tokens").await?;
    let tenants_enrollment_token_exists = column_exists(tx, "tenants", "enrollment_token").await?;
    let approvals_request_id_exists = if approvals_exists {
        column_exists(tx, "approvals", "request_id").await?
    } else {
        false
    };
    if tenant_enrollment_tokens_exists
        || (approvals_exists && approvals_request_id_exists && !tenants_enrollment_token_exists)
    {
        insert_migration_marker(tx, "003_adaptive_sdr_token_and_approval_flow.sql").await?;
    }

    if table_exists(tx, "tenant_active_policies").await? {
        insert_migration_marker(tx, "004_adaptive_sdr_active_policy.sql").await?;
    }

    if table_exists(tx, "approval_resolution_outbox").await? {
        insert_migration_marker(tx, "005_adaptive_sdr_approval_outbox.sql").await?;
    }

    Ok(())
}

/// Create a PostgreSQL connection pool from the given database URL.
pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::error::Error> {
    PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await
}

/// Apply embedded SQL migrations exactly once per database.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::error::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query::query("SELECT pg_advisory_xact_lock($1)")
        .bind(MIGRATION_LOCK_KEY)
        .execute(&mut *tx)
        .await?;

    sqlx::query::query(
        r#"CREATE TABLE IF NOT EXISTS schema_migrations (
               name TEXT PRIMARY KEY,
               applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
           )"#,
    )
    .execute(&mut *tx)
    .await?;

    backfill_legacy_migration_markers(&mut tx).await?;

    for migration in EMBEDDED_MIGRATIONS {
        let already_applied = sqlx::query::query("SELECT 1 FROM schema_migrations WHERE name = $1")
            .bind(migration.name)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if already_applied {
            continue;
        }

        sqlx::raw_sql::raw_sql(migration.sql)
            .execute(&mut *tx)
            .await?;
        sqlx::query::query("INSERT INTO schema_migrations (name) VALUES ($1)")
            .bind(migration.name)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(())
}
