//! Platform routes: accessible only to users in the builder tenant with a builder role.

use axum::{
    extract::State,
    http::header::AUTHORIZATION,
    routing::get,
    Json, Router,
};
use std::sync::Arc;

use crate::api::state::AppState;
use crate::error::AppError;

fn bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, AppError> {
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;
    auth.strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header".to_string()))
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/tenants", get(list_tenants))
}

async fn list_tenants(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let session_token = bearer_token(&headers)?;
    let payload = state
        .session_store
        .get(session_token)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired session".to_string()))?;

    if payload.tenant_id != state.builder_tenant_id {
        return Err(AppError::Forbidden(
            "Access restricted to builder tenant".to_string(),
        ));
    }

    let has_role = payload
        .roles
        .iter()
        .any(|r| state.allowed_roles.contains(r));
    if !has_role {
        return Err(AppError::Forbidden(format!(
            "Requires one of the following Builder roles: {}",
            state.allowed_roles.join(", ")
        )));
    }

    let tenants = state.tenant_state.tenants_repo.list_all().await?;
    let tenants_json: Vec<serde_json::Value> = tenants
        .into_iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "name": t.name,
                "status": t.status,
                "createdAt": t.created_at.to_rfc3339()
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "tenants": tenants_json })))
}
