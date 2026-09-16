//! Authrs - Multi-tenant authentication service entrypoint.

use authrs::api::state::AppState;
use authrs::middleware::trace::trace_id_middleware;
use authrs::routes;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    let config = authrs::Config::from_env().expect("Invalid config");

    // JSON logs by default; every line carries `trace_id` from the request span.
    // Set LOG_FORMAT=text (or pretty) for human-readable local logs.
    authrs::logging::init(&config.log_level);

    authrs::db::ensure_database_exists(&config.database_url)
        .await
        .expect("Failed to ensure database exists");
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
        config.frontend_url.clone(),
        config.builder_tenant_id.clone(),
        config.allowed_roles.clone(),
        config.default_session_ttl_secs,
    )?;
    state
        .packages_service
        .rebuild_schema()
        .await
        .expect("Failed to load Cedar schema from DB");
    let state = std::sync::Arc::new(state);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Trace span outermost: reads the incoming `traceparent` and puts `trace_id`
    // on every log line for the request (empty when no valid header is passed).
    let app = routes::router()
        .with_state(state)
        .layer(cors)
        .layer(axum::middleware::from_fn(trace_id_middleware));

    let addr = format!("{}:{}", config.server_host, config.server_port)
        .parse::<SocketAddr>()
        .expect("Invalid SERVER_HOST:PORT");
    tracing::info!("Listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
