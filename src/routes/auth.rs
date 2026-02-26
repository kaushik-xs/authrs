//! Authentication routes: login (email/username password, OTP), OAuth.

use axum::{
    extract::State,
    routing::post,
    Json, Router,
};
use serde::Deserialize;

use crate::api::state::AppState;
use crate::api::tenant::TenantId;
use crate::email;
use crate::error::AppError;
use crate::services::auth::LoginResult;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use rand::Rng;
use std::sync::Arc;

/// Signup at root path /signup
pub fn signup_router() -> Router<Arc<AppState>> {
    Router::new().route("/signup", post(signup))
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/email-password", post(login_email_password))
        .route("/username-password", post(login_username_password))
        .route("/email-otp/request", post(email_otp_request))
        .route("/mobile-otp/request", post(mobile_otp_request))
        .route("/mobile-whatsapp-otp/request", post(mobile_whatsapp_otp_request))
        .route("/otp/verify", post(otp_verify))
}

pub fn oauth_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/:provider", axum::routing::get(oauth_redirect))
        .route("/:provider/callback", axum::routing::get(oauth_callback))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailPasswordBody {
    email: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignupBody {
    first_name: String,
    last_name: String,
    email: String,
    #[serde(default)]
    mobile: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    password: String,
    retype_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsernamePasswordBody {
    username: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailOtpRequestBody {
    email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OtpVerifyBody {
    identifier: String,
    code: String,
    channel: String,
}

async fn signup(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<SignupBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let user = state
        .auth_service
        .signup(
            &tenant_id.0,
            &body.first_name,
            &body.last_name,
            &body.email,
            body.mobile.as_deref(),
            body.country_code.as_deref(),
            &body.password,
            &body.retype_password,
        )
        .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({
            "id": user.id,
            "tenantId": user.tenant_id,
            "firstName": user.first_name,
            "lastName": user.last_name,
            "email": user.email,
            "mobile": user.mobile,
            "countryCode": user.country_code,
            "status": user.status,
        })),
    ))
}

async fn login_email_password(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<EmailPasswordBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = state
        .auth_service
        .login_email_password(&tenant_id.0, &body.email, &body.password, None, None)
        .await?;
    match result {
        LoginResult::Success { session_token, expires_at } => Ok(Json(serde_json::json!({
            "sessionToken": session_token,
            "expiresAt": expires_at.to_rfc3339()
        }))),
        LoginResult::MfaRequired { mfa_token, .. } => Ok(Json(serde_json::json!({
            "mfaRequired": true,
            "mfaToken": mfa_token
        }))),
    }
}

async fn login_username_password(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<UsernamePasswordBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = state
        .auth_service
        .login_username_password(&tenant_id.0, &body.username, &body.password, None, None)
        .await?;
    match result {
        LoginResult::Success { session_token, expires_at } => Ok(Json(serde_json::json!({
            "sessionToken": session_token,
            "expiresAt": expires_at.to_rfc3339()
        }))),
        LoginResult::MfaRequired { mfa_token, .. } => Ok(Json(serde_json::json!({
            "mfaRequired": true,
            "mfaToken": mfa_token
        }))),
    }
}

async fn email_otp_request(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<EmailOtpRequestBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let smtp = state.smtp_config.as_ref().ok_or_else(|| {
        AppError::Internal("Email OTP is not configured. Set SMTP_HOST and SMTP_FROM.".to_string())
    })?;

    let email = body.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(AppError::BadRequest("email is required".to_string()));
    }

    let code: String = (0..6).map(|_| rand::thread_rng().gen_range(0..10).to_string()).collect();
    let expires_at = Utc::now() + Duration::minutes(10);

    state
        .otp_repo
        .create(
            &tenant_id.0,
            &email,
            "email",
            &code,
            "login",
            expires_at,
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if let Err(e) = email::send_otp_email(smtp, &email, &code).await {
        tracing::warn!("Failed to send OTP email to {}: {}", email, e);
        return Err(AppError::Internal("Failed to send verification email".to_string()));
    }

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "If this email is registered, you will receive a verification code shortly."
        })),
    ))
}

async fn mobile_otp_request() -> &'static str {
    "mobile otp request placeholder"
}

async fn mobile_whatsapp_otp_request() -> &'static str {
    "mobile whatsapp otp request placeholder"
}

const MAX_OTP_ATTEMPTS: i32 = 5;

async fn otp_verify(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<OtpVerifyBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let identifier = body.identifier.trim();
    let code = body.code.trim();
    let channel = body.channel.trim();
    if identifier.is_empty() || code.is_empty() || channel.is_empty() {
        return Err(AppError::BadRequest("identifier, code, and channel are required".to_string()));
    }
    if channel != "email" {
        return Err(AppError::BadRequest("Only channel 'email' is supported".to_string()));
    }
    let identifier_normalized = identifier.to_lowercase();

    let otp = state
        .otp_repo
        .get_latest(&tenant_id.0, &identifier_normalized, "email", "login")
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired code".to_string()))?;

    if otp.attempt_count >= MAX_OTP_ATTEMPTS {
        return Err(AppError::Unauthorized("Too many attempts. Request a new code.".to_string()));
    }
    if otp.code != code {
        state.otp_repo.increment_attempts(otp.id).await.map_err(|e| AppError::Internal(e.to_string()))?;
        return Err(AppError::Unauthorized("Invalid or expired code".to_string()));
    }

    let result = state
        .auth_service
        .login_with_verified_otp(&tenant_id.0, &identifier_normalized, None, None)
        .await?;

    state.otp_repo.delete(otp.id).await.map_err(|e| AppError::Internal(e.to_string()))?;

    match result {
        LoginResult::Success { session_token, expires_at } => Ok(Json(serde_json::json!({
            "sessionToken": session_token,
            "expiresAt": expires_at.to_rfc3339()
        }))),
        LoginResult::MfaRequired { mfa_token, .. } => Ok(Json(serde_json::json!({
            "mfaRequired": true,
            "mfaToken": mfa_token
        }))),
    }
}

async fn oauth_redirect() -> &'static str {
    "oauth redirect placeholder"
}

async fn oauth_callback() -> &'static str {
    "oauth callback placeholder"
}
