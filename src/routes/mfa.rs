//! MFA routes: authenticator-app (TOTP) enrollment, login validation, backup codes.
//!
//! Enrollment/management endpoints take a session Bearer token; `/mfa/validate` takes the
//! `mfaToken` returned by any login that answered `{ mfaRequired: true }`.

use axum::{
    extract::State,
    http::header::AUTHORIZATION,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::api::state::AppState;
use crate::domain::identity::Identity;
use crate::domain::session::SessionPayload;
use crate::error::AppError;
use crate::routes::auth::login_result_json;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/status", get(mfa_status))
        .route("/enable", post(mfa_enable))
        .route("/verify", post(mfa_verify))
        .route("/validate", post(mfa_validate))
        .route("/disable", post(mfa_disable))
        .route("/backup-codes", post(mfa_regenerate_backup_codes))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CodeBody {
    code: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidateBody {
    mfa_token: String,
    code: String,
}

/// Resolve the session Bearer token to its payload and global identity.
async fn session_identity(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(SessionPayload, Identity), AppError> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header".to_string()))?;
    let payload = state
        .session_store
        .get(token)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired session".to_string()))?;
    let identity = state
        .auth_service
        .identities_repo()
        .get_by_id(payload.identity_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired session".to_string()))?;
    Ok((payload, identity))
}

/// Whether MFA is on for the session's identity, and how many backup codes are left.
async fn mfa_status(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let (_, identity) = session_identity(&state, &headers).await?;
    let remaining = state.mfa_service.backup_codes_remaining(&identity).await?;
    Ok(Json(serde_json::json!({
        "enabled": identity.mfa_enabled,
        "backupCodesRemaining": remaining,
    })))
}

/// Start authenticator enrollment. Returns the secret (manual entry) and an otpauth URI to
/// render as a QR code. MFA is not active until `/mfa/verify` succeeds.
async fn mfa_enable(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let (payload, identity) = session_identity(&state, &headers).await?;
    let label = match identity.email.clone().or_else(|| {
        identity
            .mobile
            .as_ref()
            .zip(identity.country_code.as_ref())
            .map(|(m, c)| format!("{}{}", c, m))
    }) {
        Some(handle) => handle,
        None => state
            .auth_service
            .users_repo()
            .get_by_id(&payload.tenant_id, payload.user_id)
            .await?
            .and_then(|u| u.username)
            .unwrap_or_else(|| "user".to_string()),
    };
    let enrollment = state.mfa_service.begin_enrollment(&identity, &label).await?;
    Ok(Json(serde_json::json!({
        "secret": enrollment.secret,
        "otpauthUrl": enrollment.otpauth_url,
    })))
}

/// Confirm enrollment with the first code from the app. Turns MFA on and returns backup
/// codes — the only time they are shown.
async fn mfa_verify(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CodeBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (_, identity) = session_identity(&state, &headers).await?;
    let backup_codes = state.mfa_service.confirm_enrollment(&identity, &body.code).await?;
    Ok(Json(serde_json::json!({
        "enabled": true,
        "backupCodes": backup_codes,
    })))
}

/// Complete a login that returned `mfaRequired`. Accepts a TOTP code or a backup code.
async fn mfa_validate(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ValidateBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = state
        .auth_service
        .complete_mfa_login(body.mfa_token.trim(), &body.code, None, None)
        .await?;
    Ok(login_result_json(result))
}

/// Turn MFA off (requires a current TOTP or backup code).
async fn mfa_disable(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CodeBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (_, identity) = session_identity(&state, &headers).await?;
    state.mfa_service.disable(&identity, &body.code).await?;
    Ok(Json(serde_json::json!({ "enabled": false })))
}

/// Replace all backup codes (requires a current TOTP or backup code).
async fn mfa_regenerate_backup_codes(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CodeBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (_, identity) = session_identity(&state, &headers).await?;
    let backup_codes = state
        .mfa_service
        .regenerate_backup_codes(&identity, &body.code)
        .await?;
    Ok(Json(serde_json::json!({ "backupCodes": backup_codes })))
}
