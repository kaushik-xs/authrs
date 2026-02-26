//! Database seed binary: creates base data from SEED_* env vars.
//!
//! Usage:
//!   SEED_TENANT_ID=acme_corp SEED_TENANT_NAME="Acme Corp" cargo run --bin seed
//!   With admin user:
//!   SEED_TENANT_ID=acme SEED_TENANT_NAME=Acme SEED_ADMIN_EMAIL=admin@acme.com SEED_ADMIN_PASSWORD=secret cargo run --bin seed

use authrs::{seed_run, SeedInput};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&database_url)
        .await?;

    // Run migrations first so schema (and trigger for Launchpad Admins) exists
    sqlx::migrate!("./migrations").run(&pool).await?;

    let input = match SeedInput::from_env().map_err(|e| e.to_string())? {
        Some(i) => i,
        None => {
            eprintln!("Seed skipped: set SEED_TENANT_ID to run the seeder.");
            eprintln!("Example: SEED_TENANT_ID=acme SEED_TENANT_NAME=Acme SEED_ADMIN_EMAIL=admin@acme.com SEED_ADMIN_PASSWORD=secret");
            std::process::exit(0);
        }
    };

    seed_run(&pool, &input).await.map_err(|e| e.to_string())?;
    tracing::info!("Seed completed successfully.");
    Ok(())
}
