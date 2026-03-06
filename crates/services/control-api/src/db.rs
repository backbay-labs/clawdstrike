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
];

/// Create a PostgreSQL connection pool from the given database URL.
pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::error::Error> {
    PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await
}

/// Apply embedded SQL migrations exactly once per database.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::error::Error> {
    sqlx::query::query(
        r#"CREATE TABLE IF NOT EXISTS schema_migrations (
               name TEXT PRIMARY KEY,
               applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
           )"#,
    )
    .execute(pool)
    .await?;

    for migration in EMBEDDED_MIGRATIONS {
        let already_applied = sqlx::query::query("SELECT 1 FROM schema_migrations WHERE name = $1")
            .bind(migration.name)
            .fetch_optional(pool)
            .await?
            .is_some();
        if already_applied {
            continue;
        }

        let mut tx = pool.begin().await?;
        sqlx::raw_sql::raw_sql(migration.sql)
            .execute(&mut *tx)
            .await?;
        sqlx::query::query("INSERT INTO schema_migrations (name) VALUES ($1)")
            .bind(migration.name)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }

    Ok(())
}
