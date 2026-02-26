//! Session routes: validate, logout, logout all.

use axum::{
    extract::State,
    http::header::AUTHORIZATION,
    routing::{get, post},
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
    let prefix = "Bearer ";
    auth.strip_prefix(prefix)
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header".to_string()))
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/validate", get(session_validate))
        .route("/logout", post(logout))
        .route("/logout/all", post(logout_all))
}

async fn session_validate(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let session_token = bearer_token(&headers)?;
    let payload = state
        .session_store
        .get(session_token)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired session".to_string()))?;
    Ok(Json(serde_json::json!({
        "tenantId": payload.tenant_id,
        "userId": payload.user_id,
        "roles": payload.roles,
        "permissions": payload.permissions,
        "expiresAt": payload.expires_at.to_rfc3339()
    })))
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let session_token = bearer_token(&headers)?;
    let _ = state.session_store.delete(session_token).await?;
    let _ = state.sessions_repo.revoke_by_session_token(session_token).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn logout_all(
    State(state): State<Arc<AppState>>,
    tenant_id: crate::api::tenant::TenantId,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let session_token = bearer_token(&headers)?;
    let payload = state
        .session_store
        .get(session_token)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired session".to_string()))?;
    let count = state
        .session_store
        .delete_all_for_user(&tenant_id.0, payload.user_id)
        .await?;
    let _ = state.sessions_repo.revoke_all_for_user(&tenant_id.0, payload.user_id).await;
    Ok(Json(serde_json::json!({ "ok": true, "sessionsRevoked": count })))
}
