//! OpenAPI spec endpoint: GET /spec

use axum::{routing::get, Json, Router};
use std::sync::Arc;

use crate::api::state::AppState;
use crate::openapi;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/spec", get(spec_handler))
}

async fn spec_handler() -> Json<serde_json::Value> {
    let openapi = openapi::spec();
    let json = openapi
        .to_pretty_json()
        .expect("OpenAPI spec serialization");
    let value: serde_json::Value =
        serde_json::from_str(&json).expect("OpenAPI spec JSON parse");
    Json(value)
}
