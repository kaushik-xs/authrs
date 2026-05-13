//! Auth service: login (email/username password), lock policy, effective login methods.

use crate::domain::session::SessionPayload;
use crate::domain::user::{has_valid_identity, User};
use crate::error::AppError;
use crate::repo::{force_change_tokens::ForceChangeTokensRepo, password_reset_tokens::PasswordResetTokensRepo, roles::RolesRepo, users::UsersRepo};
use crate::services::session::SessionStore;
use crate::services::tenant_config::{PasswordPolicy, TenantConfigLoader};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use std::sync::Arc;
use uuid::Uuid;

const LOGIN_METHOD_EMAIL_PASSWORD: i32 = 1;
const LOGIN_METHOD_EMAIL_OTP: i32 = 2;
const LOGIN_METHOD_USERNAME_PASSWORD: i32 = 4;
const DEFAULT_LOCK_AFTER_ATTEMPTS: i32 = 5;
const DEFAULT_LOCK_DURATION_MINS: i64 = 15;
const DEFAULT_SESSION_TTL_SECS: u64 = 3600; // 1 hour
const PASSWORD_RESET_TOKEN_TTL_MINS: i64 = 60;
const FORCE_CHANGE_TOKEN_TTL_MINS: i64 = 15;

/// Generates a 256-bit (32-byte) random session token, base64url-encoded (no padding).
fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Clone)]
pub struct AuthService {
    users_repo: UsersRepo,
    roles_repo: RolesRepo,
    password_reset_tokens_repo: PasswordResetTokensRepo,
    force_change_tokens_repo: ForceChangeTokensRepo,
    tenant_config: TenantConfigLoader,
    session_store: Arc<dyn SessionStore>,
    sessions_repo: crate::repo::sessions::PostgresSessionStore,
}

impl AuthService {
    pub fn new(
        users_repo: UsersRepo,
        roles_repo: RolesRepo,
        password_reset_tokens_repo: PasswordResetTokensRepo,
        force_change_tokens_repo: ForceChangeTokensRepo,
        tenant_config: TenantConfigLoader,
        session_store: Arc<dyn SessionStore>,
        sessions_repo: crate::repo::sessions::PostgresSessionStore,
    ) -> Self {
        Self {
            users_repo,
            roles_repo,
            password_reset_tokens_repo,
            force_change_tokens_repo,
            tenant_config,
            session_store,
            sessions_repo,
        }
    }

    /// For admin routes: assign/remove roles, list user roles (roles are assigned only to users).
    pub fn roles_repo(&self) -> &RolesRepo {
        &self.roles_repo
    }

    /// For session/me and other routes that need to load user by id.
    pub fn users_repo(&self) -> &UsersRepo {
        &self.users_repo
    }

    /// Effective login methods = intersection of tenant allowed, group allowed, user supported.
    fn user_supported_methods(user: &User) -> Vec<i32> {
        let mut methods = Vec::new();
        if user.email.is_some() {
            methods.push(1); // email+password
            methods.push(2); // email+otp
        }
        if user.mobile.is_some() && user.country_code.is_some() {
            methods.push(3); // mobile+otp sms
            methods.push(6); // mobile+whatsapp otp
        }
        if user.username.is_some() {
            methods.push(4); // username+password
        }
        methods.push(5); // oauth (if user exists with email from oauth)
        methods
    }

    pub async fn effective_login_methods(
        &self,
        tenant_id: &str,
        _user_id: Uuid,
        user: &User,
    ) -> Result<Vec<i32>, AppError> {
        let tenant_allowed = self
            .tenant_config
            .get_login_methods(tenant_id)
            .await?
            .unwrap_or_else(|| vec![1, 2, 3, 4, 5, 6]);
        let user_supported = Self::user_supported_methods(user);
        let effective = tenant_allowed
            .into_iter()
            .filter(|m| user_supported.contains(m))
            .collect();
        Ok(effective)
    }

    fn verify_password(&self, hash: &str, password: &str) -> Result<bool, AppError> {
        let parsed = PasswordHash::new(hash).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    fn validate_password_policy(password: &str, policy: Option<&PasswordPolicy>) -> Result<(), AppError> {
        let Some(p) = policy else { return Ok(()); };
        if let Some(min) = p.min_length {
            if password.len() < min as usize {
                return Err(AppError::BadRequest(format!(
                    "Password must be at least {} characters",
                    min
                )));
            }
        }
        if p.require_uppercase == Some(true) && !password.chars().any(|c| c.is_uppercase()) {
            return Err(AppError::BadRequest(
                "Password must contain at least one uppercase letter".to_string(),
            ));
        }
        if p.require_digit == Some(true) && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(AppError::BadRequest(
                "Password must contain at least one digit".to_string(),
            ));
        }
        Ok(())
    }

    fn hash_password(&self, password: &str) -> Result<String, AppError> {
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .to_string();
        Ok(hash)
    }

    pub async fn login_email_password(
        &self,
        tenant_id: &str,
        email: &str,
        password: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LoginResult, AppError> {
        let user = self
            .users_repo
            .get_by_email(tenant_id, email)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid email or password".to_string()))?;
        self.do_password_login(tenant_id, &user, password, ip, user_agent, LOGIN_METHOD_EMAIL_PASSWORD)
            .await
    }

    pub async fn login_username_password(
        &self,
        tenant_id: &str,
        username: &str,
        password: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LoginResult, AppError> {
        let user = self
            .users_repo
            .get_by_username(tenant_id, username)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid username or password".to_string()))?;
        self.do_password_login(tenant_id, &user, password, ip, user_agent, LOGIN_METHOD_USERNAME_PASSWORD)
            .await
    }

    async fn do_password_login(
        &self,
        tenant_id: &str,
        user: &User,
        password: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
        method: i32,
    ) -> Result<LoginResult, AppError> {
        if user.status != "active" {
            return Err(AppError::Forbidden("Account is not active".to_string()));
        }
        if let Some(locked_until) = user.locked_until {
            if locked_until > Utc::now() {
                return Err(AppError::Locked("Account is temporarily locked".to_string()));
            }
        }
        let effective = self.effective_login_methods(tenant_id, user.id, user).await?;
        if !effective.contains(&method) {
            return Err(AppError::Forbidden("This login method is not allowed for your account".to_string()));
        }
        let password_hash = user
            .password_hash
            .as_ref()
            .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
        if !self.verify_password(password_hash, password)? {
            let policy = self.tenant_config.get_password_policy(tenant_id).await?;
            let lock_after = policy
                .and_then(|p| p.max_age_days)
                .map(|_| DEFAULT_LOCK_AFTER_ATTEMPTS)
                .unwrap_or(DEFAULT_LOCK_AFTER_ATTEMPTS);
            let lock_until = if user.failed_attempts + 1 >= lock_after {
                Some(Utc::now() + Duration::minutes(DEFAULT_LOCK_DURATION_MINS))
            } else {
                None
            };
            self.users_repo
                .increment_failed_attempts(tenant_id, user.id, lock_until)
                .await?;
            return Err(AppError::Unauthorized("Invalid email or password".to_string()));
        }
        self.users_repo.clear_failed_attempts(tenant_id, user.id).await?;

        if user.force_password_change {
            return self.issue_force_change_token(tenant_id, user.id).await;
        }

        if user.mfa_enabled {
            return Ok(LoginResult::MfaRequired {
                mfa_token: Uuid::new_v4().to_string(),
                user_id: user.id,
            });
        }

        self.do_create_session(tenant_id, user, ip, user_agent).await
    }

    /// Create a session for a user (after password or OTP verified). Caller must have checked status, lock, and login method.
    async fn do_create_session(
        &self,
        tenant_id: &str,
        user: &User,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LoginResult, AppError> {
        let roles = self.roles_repo.get_user_roles(tenant_id, user.id).await.unwrap_or_default();
        let permissions = self
            .roles_repo
            .get_user_permissions(tenant_id, user.id)
            .await
            .unwrap_or_default();
        let session_policy = self.tenant_config.get_session_policy(tenant_id).await?;
        let ttl_secs = session_policy
            .and_then(|p| p.absolute_timeout_mins)
            .map(|m| m * 60)
            .unwrap_or(DEFAULT_SESSION_TTL_SECS);
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
        let session_token = generate_session_token();
        let payload = SessionPayload {
            tenant_id: tenant_id.to_string(),
            user_id: user.id,
            roles,
            permissions,
            ip: ip.map(String::from),
            user_agent: user_agent.map(String::from),
            expires_at,
        };
        self.session_store
            .set(&session_token, &payload, ttl_secs)
            .await?;
        if !self.session_store.writes_audit_row() {
            self.sessions_repo
                .create_audit(
                    &session_token,
                    tenant_id,
                    user.id,
                    ip,
                    user_agent,
                    expires_at,
                    Some(&serde_json::to_string(&payload).unwrap()),
                )
                .await?;
        }
        Ok(LoginResult::Success {
            session_token,
            expires_at,
        })
    }

    /// Login with verified OTP (caller has already validated the code). Identifier is normalized email for channel=email.
    pub async fn login_with_verified_otp(
        &self,
        tenant_id: &str,
        email: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LoginResult, AppError> {
        let user = self
            .users_repo
            .get_by_email_insensitive(tenant_id, email)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid or expired code".to_string()))?;

        if user.status != "active" {
            return Err(AppError::Forbidden("Account is not active".to_string()));
        }
        if let Some(locked_until) = user.locked_until {
            if locked_until > Utc::now() {
                return Err(AppError::Locked("Account is temporarily locked".to_string()));
            }
        }
        let effective = self.effective_login_methods(tenant_id, user.id, &user).await?;
        if !effective.contains(&LOGIN_METHOD_EMAIL_OTP) {
            return Err(AppError::Forbidden("Email OTP login is not allowed for your account".to_string()));
        }

        if user.force_password_change {
            return self.issue_force_change_token(tenant_id, user.id).await;
        }

        if user.mfa_enabled {
            return Ok(LoginResult::MfaRequired {
                mfa_token: Uuid::new_v4().to_string(),
                user_id: user.id,
            });
        }

        self.do_create_session(tenant_id, &user, ip, user_agent).await
    }

    /// Sign up a new user with email (required), optional mobile, and password.
    /// Validates password match and tenant password policy; returns Conflict if email already exists.
    pub async fn signup(
        &self,
        tenant_id: &str,
        first_name: &str,
        last_name: &str,
        email: &str,
        mobile: Option<&str>,
        country_code: Option<&str>,
        password: &str,
        retype_password: &str,
    ) -> Result<User, AppError> {
        let email = email.trim();
        if email.is_empty() {
            return Err(AppError::BadRequest("Email is required".to_string()));
        }
        if password != retype_password {
            return Err(AppError::BadRequest("Password and retype password do not match".to_string()));
        }
        let policy = self.tenant_config.get_password_policy(tenant_id).await?;
        Self::validate_password_policy(password, policy.as_ref())?;
        if self.users_repo.get_by_email(tenant_id, email).await?.is_some() {
            return Err(AppError::Conflict("An account with this email already exists".to_string()));
        }
        if let (Some(m), Some(c)) = (mobile, country_code) {
            if !m.trim().is_empty() && c.trim().is_empty() {
                return Err(AppError::BadRequest(
                    "Country code is required when mobile is provided".to_string(),
                ));
            }
        }
        let password_hash = self.hash_password(password)?;
        let user = self
            .users_repo
            .create(
                tenant_id,
                Some(first_name.trim()).filter(|s| !s.is_empty()),
                Some(last_name.trim()).filter(|s| !s.is_empty()),
                Some(email),
                None,
                mobile.map(|s| s.trim()).filter(|s| !s.is_empty()),
                country_code.map(|s| s.trim()).filter(|s| !s.is_empty()),
                Some(&password_hash),
            )
            .await?;
        Ok(user)
    }

    /// Forgot password: create a reset token. Returns Some((email, token)) when user exists so caller can send email; None to avoid email enumeration.
    pub async fn forgot_password(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<(String, String)>, AppError> {
        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Err(AppError::BadRequest("Email is required".to_string()));
        }
        let user = match self.users_repo.get_by_email_insensitive(tenant_id, &email).await? {
            Some(u) => u,
            None => return Ok(None),
        };
        let to_email = match &user.email {
            Some(e) => e.clone(),
            None => return Ok(None),
        };
        self.password_reset_tokens_repo
            .delete_for_user(tenant_id, user.id)
            .await?;
        let token = generate_session_token();
        let expires_at = Utc::now() + Duration::minutes(PASSWORD_RESET_TOKEN_TTL_MINS);
        self.password_reset_tokens_repo
            .create(tenant_id, user.id, &token, expires_at)
            .await?;
        Ok(Some((to_email, token)))
    }

    /// Reset password using a token from forgot-password email. Validates token, applies policy, updates password, invalidates token.
    pub async fn reset_password(
        &self,
        tenant_id: &str,
        token: &str,
        new_password: &str,
        retype_password: &str,
    ) -> Result<(), AppError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(AppError::BadRequest("Token is required".to_string()));
        }
        if new_password != retype_password {
            return Err(AppError::BadRequest("Password and retype password do not match".to_string()));
        }
        let policy = self.tenant_config.get_password_policy(tenant_id).await?;
        Self::validate_password_policy(new_password, policy.as_ref())?;
        let (stored_tenant_id, user_id) = self
            .password_reset_tokens_repo
            .get_valid(token)
            .await?
            .ok_or_else(|| AppError::BadRequest("Invalid or expired reset token".to_string()))?;
        if stored_tenant_id != tenant_id {
            return Err(AppError::BadRequest("Invalid or expired reset token".to_string()));
        }
        let password_hash = self.hash_password(new_password)?;
        self.users_repo
            .update_password(tenant_id, user_id, &password_hash)
            .await?;
        self.password_reset_tokens_repo.delete_by_token(token).await?;
        Ok(())
    }

    /// Change password for the current user (requires current password).
    pub async fn change_password(
        &self,
        tenant_id: &str,
        user_id: Uuid,
        current_password: &str,
        new_password: &str,
        retype_password: &str,
    ) -> Result<(), AppError> {
        if new_password != retype_password {
            return Err(AppError::BadRequest("Password and retype password do not match".to_string()));
        }
        let policy = self.tenant_config.get_password_policy(tenant_id).await?;
        Self::validate_password_policy(new_password, policy.as_ref())?;
        let user = self
            .users_repo
            .get_by_id(tenant_id, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
        let password_hash = user
            .password_hash
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("Account has no password set".to_string()))?;
        if !self.verify_password(password_hash, current_password)? {
            return Err(AppError::Unauthorized("Current password is incorrect".to_string()));
        }
        let new_hash = self.hash_password(new_password)?;
        self.users_repo
            .update_password(tenant_id, user_id, &new_hash)
            .await?;
        Ok(())
    }

    /// Admin reset: set a new password for a user (no current password required). Caller is responsible for admin auth.
    pub async fn admin_reset_password(
        &self,
        tenant_id: &str,
        user_id: Uuid,
        new_password: &str,
        retype_password: &str,
        force_password_change: bool,
    ) -> Result<(), AppError> {
        if new_password != retype_password {
            return Err(AppError::BadRequest("Password and retype password do not match".to_string()));
        }
        let policy = self.tenant_config.get_password_policy(tenant_id).await?;
        Self::validate_password_policy(new_password, policy.as_ref())?;
        let _user = self
            .users_repo
            .get_by_id(tenant_id, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
        let password_hash = self.hash_password(new_password)?;
        self.users_repo
            .update_password(tenant_id, user_id, &password_hash)
            .await?;
        self.users_repo
            .set_force_password_change(tenant_id, user_id, force_password_change)
            .await?;
        Ok(())
    }

    async fn issue_force_change_token(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<LoginResult, AppError> {
        let change_token = generate_session_token();
        let expires_at = Utc::now() + Duration::minutes(FORCE_CHANGE_TOKEN_TTL_MINS);
        self.force_change_tokens_repo
            .create(tenant_id, user_id, &change_token, expires_at)
            .await?;
        Ok(LoginResult::PasswordChangeRequired { change_token })
    }

    /// Complete a forced password change using a change_token issued at login.
    pub async fn force_change_password(
        &self,
        change_token: &str,
        new_password: &str,
        retype_password: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LoginResult, AppError> {
        let (tenant_id, user_id) = self
            .force_change_tokens_repo
            .get_valid(change_token)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid or expired change token".to_string()))?;

        if new_password != retype_password {
            return Err(AppError::BadRequest("Password and retype password do not match".to_string()));
        }
        let policy = self.tenant_config.get_password_policy(&tenant_id).await?;
        Self::validate_password_policy(new_password, policy.as_ref())?;

        let user = self
            .users_repo
            .get_by_id(&tenant_id, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let password_hash = self.hash_password(new_password)?;
        self.users_repo.update_password(&tenant_id, user_id, &password_hash).await?;
        self.users_repo.set_force_password_change(&tenant_id, user_id, false).await?;
        self.force_change_tokens_repo.delete_by_token(change_token).await?;

        self.do_create_session(&tenant_id, &user, ip, user_agent).await
    }

    /// Admin create user: at least one of email, (mobile+country_code), or username required.
    /// If password is provided, retype_password must match and policy is applied.
    pub async fn admin_create_user(
        &self,
        tenant_id: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        email: Option<&str>,
        username: Option<&str>,
        mobile: Option<&str>,
        country_code: Option<&str>,
        password: Option<&str>,
        retype_password: Option<&str>,
    ) -> Result<User, AppError> {
        let email = email.map(|s| s.trim()).filter(|s| !s.is_empty());
        let username = username.map(|s| s.trim()).filter(|s| !s.is_empty());
        let mobile = mobile.map(|s| s.trim()).filter(|s| !s.is_empty());
        let country_code = country_code.map(|s| s.trim()).filter(|s| !s.is_empty());
        let email_opt = email.map(String::from);
        let mobile_opt = mobile.map(String::from);
        let country_code_opt = country_code.map(String::from);
        let username_opt = username.map(String::from);
        if !has_valid_identity(&email_opt, &mobile_opt, &country_code_opt, &username_opt) {
            return Err(AppError::BadRequest(
                "At least one of email, (mobile and countryCode), or username is required".to_string(),
            ));
        }
        if let Some(email_str) = email {
            if self.users_repo.get_by_email(tenant_id, email_str).await?.is_some() {
                return Err(AppError::Conflict("An account with this email already exists".to_string()));
            }
        }
        if let Some(username_str) = username {
            if self.users_repo.get_by_username(tenant_id, username_str).await?.is_some() {
                return Err(AppError::Conflict("An account with this username already exists".to_string()));
            }
        }
        let password_hash = match (password, retype_password) {
            (Some(p), Some(r)) => {
                if p != r {
                    return Err(AppError::BadRequest("Password and retype password do not match".to_string()));
                }
                let policy = self.tenant_config.get_password_policy(tenant_id).await?;
                Self::validate_password_policy(p, policy.as_ref())?;
                Some(self.hash_password(p)?)
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(AppError::BadRequest("Both password and retypePassword are required when setting a password".to_string()));
            }
            (None, None) => None,
        };
        let user = self
            .users_repo
            .create(
                tenant_id,
                first_name.map(|s| s.trim()).filter(|s| !s.is_empty()),
                last_name.map(|s| s.trim()).filter(|s| !s.is_empty()),
                email,
                username,
                mobile,
                country_code,
                password_hash.as_deref(),
            )
            .await?;
        Ok(user)
    }

    pub async fn admin_archive_user(&self, tenant_id: &str, user_id: Uuid) -> Result<(), AppError> {
        let _user = self
            .users_repo
            .get_by_id(tenant_id, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
        let archived = self.users_repo.archive(tenant_id, user_id).await?;
        if !archived {
            return Err(AppError::BadRequest("User is already archived".to_string()));
        }
        Ok(())
    }
}

pub enum LoginResult {
    Success {
        session_token: String,
        expires_at: chrono::DateTime<Utc>,
    },
    MfaRequired {
        mfa_token: String,
        user_id: Uuid,
    },
    PasswordChangeRequired {
        change_token: String,
    },
}
