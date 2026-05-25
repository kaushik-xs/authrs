//! Package routes: POST /admin/packages/sync, GET /admin/packages/actions

use axum::{extract::State, routing::{get, post}, Json, Router};
use serde::Deserialize;
use std::collections::HashMap;
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
    Router::new()
        .route("/packages/sync", post(sync_package))
        .route("/packages/actions", get(list_actions))
}

async fn list_actions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let pairs = state.packages_service.list_all_actions().await?;

    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for (pkg_id, action_name) in pairs {
        map.entry(pkg_id).or_default().push(action_name);
    }

    let mut packages: Vec<serde_json::Value> = map
        .into_iter()
        .map(|(pkg_id, mut actions)| {
            actions.sort();
            serde_json::json!({ "packageId": pkg_id, "actions": actions })
        })
        .collect();
    packages.sort_by(|a, b| {
        a["packageId"]
            .as_str()
            .unwrap_or("")
            .cmp(b["packageId"].as_str().unwrap_or(""))
    });

    Ok(Json(serde_json::json!({ "packages": packages })))
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
