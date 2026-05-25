//! Package sync route: POST /admin/packages/sync

use axum::{extract::State, routing::post, Json, Router};
use serde::Deserialize;
use std::sync::Arc;

use crate::api::state::AppState;
use crate::error::AppError;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncPackageBody {
    package_id: String,
    tables: Vec<String>,
    #[serde(default)]
    custom_actions: Vec<String>,
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/packages/sync", post(sync_package))
}

async fn sync_package(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SyncPackageBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    if body.package_id.trim().is_empty() {
        return Err(AppError::BadRequest("packageId is required".to_string()));
    }

    state
        .packages_service
        .sync(&body.package_id, &body.tables, &body.custom_actions)
        .await?;

    Ok(Json(serde_json::json!({
        "message": "Package synced and Cedar schema rebuilt",
        "packageId": body.package_id,
        "tables": body.tables.len(),
        "customActions": body.custom_actions.len()
    })))
}
