use sqlx_postgres::{PgPoolOptions, Postgres};

/// PostgreSQL connection pool type alias.
pub type PgPool = sqlx::pool::Pool<Postgres>;
pub type PgRow = sqlx_postgres::PgRow;

/// Create a PostgreSQL connection pool from the given database URL.
pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::error::Error> {
    PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await
}
