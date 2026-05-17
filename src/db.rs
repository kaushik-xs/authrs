//! Database initialization helpers.

use sqlx::migrate::MigrateDatabase;
use sqlx::Postgres;

/// Ensure the database referenced by `database_url` exists, creating it if missing.
///
/// Connects to the Postgres server (via the maintenance `postgres` database) to check
/// for the target database and creates it when absent. This lets the service bootstrap
/// against a fresh server without an out-of-band `createdb` step.
pub async fn ensure_database_exists(database_url: &str) -> Result<(), sqlx::Error> {
    if !Postgres::database_exists(database_url).await? {
        tracing::info!("Target database does not exist; creating it");
        Postgres::create_database(database_url).await?;
    }
    Ok(())
}
