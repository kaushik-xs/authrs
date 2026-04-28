//! Session routes: validate, logout, logout all, change password.

use axum::{
    extract::State,
    http::header::AUTHORIZATION,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::auth::LoginResult;

fn bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, AppError> {
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;
    let prefix = "Bearer ";
    auth.strip_prefix(prefix)
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header".to_string()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePasswordBody {
    current_password: String,
    new_password: String,
    retype_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ForceChangePasswordBody {
    change_token: String,
    new_password: String,
    retype_password: String,
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/validate", get(session_validate))
        .route("/me", get(session_me))
        .route("/change-password", post(change_password))
        .route("/force-change-password", post(force_change_password))
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

async fn session_me(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let session_token = bearer_token(&headers)?;
    let payload = state
        .session_store
        .get(session_token)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired session".to_string()))?;
    let user = state
        .auth_service
        .users_repo()
        .get_by_id(&payload.tenant_id, payload.user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user_json = serde_json::to_value(&user).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "userId": payload.user_id,
        "roles": payload.roles,
        "permissions": payload.permissions,
        "expiresAt": payload.expires_at.to_rfc3339(),
        "user": user_json
    })))
}

async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ChangePasswordBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session_token = bearer_token(&headers)?;
    let payload = state
        .session_store
        .get(session_token)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired session".to_string()))?;
    state
        .auth_service
        .change_password(
            &payload.tenant_id,
            payload.user_id,
            &body.current_password,
            &body.new_password,
            &body.retype_password,
        )
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Password changed successfully."
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

async fn force_change_password(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ForceChangePasswordBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = state
        .auth_service
        .force_change_password(
            &body.change_token,
            &body.new_password,
            &body.retype_password,
            None,
            None,
        )
        .await?;
    match result {
        LoginResult::Success { session_token, expires_at } => Ok(Json(serde_json::json!({
            "sessionToken": session_token,
            "expiresAt": expires_at.to_rfc3339()
        }))),
        _ => Err(AppError::Internal("Unexpected login state after password change".to_string())),
    }
}
