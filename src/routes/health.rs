//! Health and metrics endpoints.

use axum::{routing::get, Router};

use crate::api::state::AppState;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
}

async fn health_handler() -> &'static str {
    "OK"
}

async fn metrics_handler() -> &'static str {
    "# Metrics placeholder\n"
}