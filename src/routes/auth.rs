//! Authentication routes: login (email/username password, OTP), OAuth.

use axum::{
    extract::State,
    http::header::AUTHORIZATION,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use crate::api::state::AppState;
use crate::api::tenant::TenantId;
use crate::email;
use crate::error::AppError;
use crate::services::auth::{LoginResult, SignupOutcome};
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use rand::Rng;
use std::sync::Arc;

fn bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, AppError> {
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;
    auth.strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header".to_string()))
}

/// Signup at root path /signup
pub fn signup_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/signup", post(signup))
        .route("/signup/verify", post(verify_membership))
}

/// Forgot password and reset password (no auth required).
pub fn password_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/email-password", post(login_email_password))
        .route("/username-password", post(login_username_password))
        .route("/email-otp/request", post(email_otp_request))
        .route("/mobile-otp/request", post(mobile_otp_request))
        .route("/mobile-whatsapp-otp/request", post(mobile_whatsapp_otp_request))
        .route("/otp/verify", post(otp_verify))
        // SSO: tenant-less identity login + tenant selection (no X-Tenant-ID).
        .route("/identity", post(login_identity))
        .route("/select-tenant", post(select_tenant))
}

/// SSO identity endpoints mounted at root (e.g. GET /identity/tenants).
pub fn identity_router() -> Router<Arc<AppState>> {
    Router::new().route("/identity/tenants", get(identity_tenants))
}

/// Render a `LoginResult` to the standard login JSON shape.
fn login_result_json(result: LoginResult) -> Json<serde_json::Value> {
    match result {
        LoginResult::Success { session_token, expires_at } => Json(serde_json::json!({
            "sessionToken": session_token,
            "expiresAt": expires_at.to_rfc3339()
        })),
        LoginResult::MfaRequired { mfa_token, .. } => Json(serde_json::json!({
            "mfaRequired": true,
            "mfaToken": mfa_token
        })),
        LoginResult::PasswordChangeRequired { change_token } => Json(serde_json::json!({
            "passwordChangeRequired": true,
            "changeToken": change_token
        })),
    }
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ForgotPasswordBody {
    email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResetPasswordBody {
    token: String,
    new_password: String,
    retype_password: String,
}

async fn signup(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<SignupBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let outcome = state
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
    match outcome {
        SignupOutcome::Created(user) => Ok((
            axum::http::StatusCode::CREATED,
            Json(serde_json::json!({
                "id": user.id,
                "firstName": user.first_name,
                "lastName": user.last_name,
                "email": user.email,
                "mobile": user.mobile,
                "countryCode": user.country_code,
                "status": user.status,
            })),
        )),
        SignupOutcome::VerificationSent { email: to_email, token } => {
            // The email already belongs to a global identity: email the owner a verify link
            // to join this tenant. Response is intentionally generic (no enumeration).
            if let Some(ref smtp) = state.smtp_config {
                let base_url = state
                    .tenant_state
                    .tenant_config
                    .get_frontend_base_url(&tenant_id.0)
                    .await?
                    .or_else(|| state.frontend_url.clone());
                let link = base_url.map(|base| {
                    format!("{}/verify-membership?token={}", base.trim_end_matches('/'), token)
                });
                if let Err(e) =
                    email::send_membership_invite_email(smtp, &to_email, &token, link.as_deref()).await
                {
                    tracing::warn!("Failed to send membership invite email to {}: {}", to_email, e);
                }
            }
            Ok((
                axum::http::StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "message": "Registration received. If further steps are required, we've emailed you instructions."
                })),
            ))
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyMembershipBody {
    token: String,
}

/// Accept a membership invite from the verify-to-join email (no X-Tenant-ID; the tenant is
/// encoded in the token). Creates the membership for the existing identity.
async fn verify_membership(
    State(state): State<Arc<AppState>>,
    Json(body): Json<VerifyMembershipBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let user = state
        .auth_service
        .verify_membership_invite(&body.token)
        .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({
            "id": user.id,
            "tenantId": user.tenant_id,
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
        LoginResult::PasswordChangeRequired { change_token } => Ok(Json(serde_json::json!({
            "passwordChangeRequired": true,
            "changeToken": change_token
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
        LoginResult::PasswordChangeRequired { change_token } => Ok(Json(serde_json::json!({
            "passwordChangeRequired": true,
            "changeToken": change_token
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
    state.auth_service.ensure_email_domain_allowed(&tenant_id.0, &email).await?;

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
        LoginResult::PasswordChangeRequired { change_token } => Ok(Json(serde_json::json!({
            "passwordChangeRequired": true,
            "changeToken": change_token
        }))),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityLoginBody {
    email: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SelectTenantBody {
    tenant_id: String,
}

/// Tenant-less SSO login by email. Returns a short-lived identity token plus the tenants
/// this identity belongs to. No X-Tenant-ID required.
async fn login_identity(
    State(state): State<Arc<AppState>>,
    Json(body): Json<IdentityLoginBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (identity_token, tenants) = state
        .auth_service
        .login_identity(&body.email, &body.password)
        .await?;
    Ok(Json(serde_json::json!({
        "identityToken": identity_token,
        "tenants": tenants,
    })))
}

/// List the tenants for an identity token (the SSO tenant picker). Bearer = identity token.
async fn identity_tenants(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let identity_token = bearer_token(&headers)?;
    let tenants = state
        .auth_service
        .tenants_for_identity_token(identity_token)
        .await?;
    Ok(Json(serde_json::json!({ "tenants": tenants })))
}

/// Exchange an identity token (Bearer) for a tenant-scoped session.
async fn select_tenant(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SelectTenantBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let identity_token = bearer_token(&headers)?;
    let result = state
        .auth_service
        .select_tenant_with_token(identity_token, &body.tenant_id, None, None)
        .await?;
    Ok(login_result_json(result))
}

async fn forgot_password(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<ForgotPasswordBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let result = state
        .auth_service
        .forgot_password(&tenant_id.0, &body.email)
        .await?;
    if let Some((to_email, token)) = result {
        if let Some(ref smtp) = state.smtp_config {
            // Resolve the reset-link base URL: per-tenant config first, then global env fallback.
            let base_url = state
                .tenant_state
                .tenant_config
                .get_frontend_base_url(&tenant_id.0)
                .await?
                .or_else(|| state.frontend_url.clone());
            let reset_link = base_url.map(|base| {
                format!("{}/reset-password?token={}", base.trim_end_matches('/'), token)
            });
            if reset_link.is_none() {
                tracing::warn!(
                    "No frontend base URL configured for tenant {}; sending raw reset token instead of a link",
                    tenant_id.0
                );
            }
            if let Err(e) =
                email::send_password_reset_email(smtp, &to_email, &token, reset_link.as_deref()).await
            {
                tracing::warn!("Failed to send password reset email to {}: {}", to_email, e);
            }
        }
    }
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "If this email is registered, you will receive a password reset link shortly."
        })),
    ))
}

async fn reset_password(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<ResetPasswordBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    state
        .auth_service
        .reset_password(
            &tenant_id.0,
            &body.token,
            &body.new_password,
            &body.retype_password,
        )
        .await?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Password has been reset successfully."
        })),
    ))
}

async fn oauth_redirect() -> &'static str {
    "oauth redirect placeholder"
}

async fn oauth_callback() -> &'static str {
    "oauth callback placeholder"
}

pub fn availability_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/check-availability/email", post(check_email_availability))
        .route("/check-availability/username", post(check_username_availability))
        .route("/check-availability/mobile", post(check_mobile_availability))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckEmailBody {
    email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckUsernameBody {
    username: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckMobileBody {
    mobile: String,
    country_code: String,
}

async fn check_email_availability(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    headers: axum::http::HeaderMap,
    Json(body): Json<CheckEmailBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = bearer_token(&headers)?;
    state
        .session_store
        .get(token)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired session".to_string()))?;

    let email = body.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(AppError::BadRequest("email is required".to_string()));
    }

    // Email is a GLOBAL identity handle, so availability is checked across all tenants.
    let _ = &tenant_id;
    let exists = state
        .auth_service
        .identities_repo()
        .exists_by_email(&email)
        .await?;
    Ok(Json(serde_json::json!({ "available": !exists })))
}

async fn check_username_availability(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    headers: axum::http::HeaderMap,
    Json(body): Json<CheckUsernameBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = bearer_token(&headers)?;
    state
        .session_store
        .get(token)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired session".to_string()))?;

    let username = body.username.trim().to_string();
    if username.is_empty() {
        return Err(AppError::BadRequest("username is required".to_string()));
    }

    let exists = state
        .auth_service
        .users_repo()
        .exists_by_username(&tenant_id.0, &username)
        .await?;
    Ok(Json(serde_json::json!({ "available": !exists })))
}

async fn check_mobile_availability(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    headers: axum::http::HeaderMap,
    Json(body): Json<CheckMobileBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = bearer_token(&headers)?;
    state
        .session_store
        .get(token)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid or expired session".to_string()))?;

    let mobile = body.mobile.trim().to_string();
    let country_code = body.country_code.trim().to_string();
    if mobile.is_empty() {
        return Err(AppError::BadRequest("mobile is required".to_string()));
    }
    if country_code.is_empty() {
        return Err(AppError::BadRequest("countryCode is required".to_string()));
    }

    // Mobile is a GLOBAL identity handle, so availability is checked across all tenants.
    let _ = &tenant_id;
    let exists = state
        .auth_service
        .identities_repo()
        .exists_by_mobile(&country_code, &mobile)
        .await?;
    Ok(Json(serde_json::json!({ "available": !exists })))
}
