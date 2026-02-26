//! Authrs - Multi-tenant authentication service entrypoint.

use authrs::api::state::AppState;
use authrs::routes;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    let config = authrs::Config::from_env().expect("Invalid config");

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&config.log_level))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to database");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let redis_url = if config.redis_configured() {
        config.redis_url.clone()
    } else {
        None
    };
    let state = AppState::new(
        pool,
        config.kv_store_encryption_key.clone(),
        redis_url,
        config.smtp_config(),
    )?;
    let state = std::sync::Arc::new(state);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = routes::router().with_state(state).layer(cors);

    let addr = format!("{}:{}", config.server_host, config.server_port)
        .parse::<SocketAddr>()
        .expect("Invalid SERVER_HOST:PORT");
    tracing::info!("Listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
