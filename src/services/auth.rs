//! Auth service: login (email/username password), lock policy, effective login methods.

use crate::domain::identity::Identity;
use crate::domain::session::SessionPayload;
use crate::domain::user::{has_valid_identity, User};
use crate::error::AppError;
use crate::repo::{force_change_tokens::ForceChangeTokensRepo, groups::GroupsRepo, identities::IdentitiesRepo, identity_tokens::IdentityTokensRepo, membership_invites::MembershipInvitesRepo, password_reset_tokens::PasswordResetTokensRepo, roles::RolesRepo, users::UsersRepo};
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

/// Chain two vecs and deduplicate, preserving the first-seen order.
fn dedup_chain<T: Eq + std::hash::Hash + Clone>(a: Vec<T>, b: Vec<T>) -> Vec<T> {
    let mut seen = std::collections::HashSet::new();
    a.into_iter().chain(b).filter(|v| seen.insert(v.clone())).collect()
}

const LOGIN_METHOD_EMAIL_PASSWORD: i32 = 1;
const LOGIN_METHOD_EMAIL_OTP: i32 = 2;
const LOGIN_METHOD_USERNAME_PASSWORD: i32 = 4;
const DEFAULT_LOCK_AFTER_ATTEMPTS: i32 = 5;
const DEFAULT_LOCK_DURATION_MINS: i64 = 15;
/// Hard-coded fallback used only if no TTL is injected. The effective default is
/// supplied via config (env `DEFAULT_SESSION_TTL_SECS`) into `AuthService`.
const DEFAULT_SESSION_TTL_SECS: u64 = 3600; // 1 hour
const PASSWORD_RESET_TOKEN_TTL_MINS: i64 = 60;
const FORCE_CHANGE_TOKEN_TTL_MINS: i64 = 15;
/// Identity token (tenant-less SSO login → tenant selection) lifetime.
const IDENTITY_TOKEN_TTL_MINS: i64 = 10;

/// Generates a 256-bit (32-byte) random session token, base64url-encoded (no padding).
fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Clone)]
pub struct AuthService {
    users_repo: UsersRepo,
    identities_repo: IdentitiesRepo,
    identity_tokens_repo: IdentityTokensRepo,
    membership_invites_repo: MembershipInvitesRepo,
    roles_repo: RolesRepo,
    groups_repo: GroupsRepo,
    password_reset_tokens_repo: PasswordResetTokensRepo,
    force_change_tokens_repo: ForceChangeTokensRepo,
    tenant_config: TenantConfigLoader,
    session_store: Arc<dyn SessionStore>,
    sessions_repo: crate::repo::sessions::PostgresSessionStore,
    /// Global fallback session TTL (seconds), used when a tenant has no
    /// `session_policy.absoluteTimeoutMins`. Sourced from `DEFAULT_SESSION_TTL_SECS` env.
    default_session_ttl_secs: u64,
}

impl AuthService {
    pub fn new(
        users_repo: UsersRepo,
        identities_repo: IdentitiesRepo,
        identity_tokens_repo: IdentityTokensRepo,
        membership_invites_repo: MembershipInvitesRepo,
        roles_repo: RolesRepo,
        groups_repo: GroupsRepo,
        password_reset_tokens_repo: PasswordResetTokensRepo,
        force_change_tokens_repo: ForceChangeTokensRepo,
        tenant_config: TenantConfigLoader,
        session_store: Arc<dyn SessionStore>,
        sessions_repo: crate::repo::sessions::PostgresSessionStore,
        default_session_ttl_secs: u64,
    ) -> Self {
        Self {
            users_repo,
            identities_repo,
            identity_tokens_repo,
            membership_invites_repo,
            roles_repo,
            groups_repo,
            password_reset_tokens_repo,
            force_change_tokens_repo,
            tenant_config,
            session_store,
            sessions_repo,
            default_session_ttl_secs: if default_session_ttl_secs > 0 {
                default_session_ttl_secs
            } else {
                DEFAULT_SESSION_TTL_SECS
            },
        }
    }

    pub fn roles_repo(&self) -> &RolesRepo {
        &self.roles_repo
    }

    pub fn groups_repo(&self) -> &GroupsRepo {
        &self.groups_repo
    }

    pub fn users_repo(&self) -> &UsersRepo {
        &self.users_repo
    }

    pub fn identities_repo(&self) -> &IdentitiesRepo {
        &self.identities_repo
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

    /// Enforce the tenant's email-domain allowlist (kv_store group "email_policy",
    /// key "allowed_domains" -> JSON array of domains). No allowlist, or an empty
    /// one, permits all domains. Matching is case-insensitive on the part after `@`.
    pub async fn ensure_email_domain_allowed(&self, tenant_id: &str, email: &str) -> Result<(), AppError> {
        let allowed = match self.tenant_config.get_allowed_email_domains(tenant_id).await? {
            Some(list) if !list.is_empty() => list,
            _ => return Ok(()),
        };
        let domain = match email.trim().rsplit_once('@') {
            Some((_, d)) if !d.is_empty() => d.to_lowercase(),
            _ => return Err(AppError::Forbidden("Email domain is not permitted".to_string())),
        };
        let permitted = allowed
            .iter()
            .any(|d| d.trim().trim_start_matches('@').to_lowercase() == domain);
        if !permitted {
            return Err(AppError::Forbidden("Email domain is not permitted".to_string()));
        }
        Ok(())
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
        self.ensure_email_domain_allowed(tenant_id, email).await?;
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

    /// Load the global identity behind a membership.
    async fn load_identity(&self, identity_id: Uuid) -> Result<Identity, AppError> {
        self.identities_repo
            .get_by_id(identity_id)
            .await?
            .ok_or_else(|| AppError::Internal("Identity not found for membership".to_string()))
    }

    /// Gates common to every login: per-tenant membership status/access (layered) plus the
    /// global identity status and lockout.
    fn check_gates(user: &User, identity: &Identity) -> Result<(), AppError> {
        if user.status != "active" || identity.status != "active" {
            return Err(AppError::Forbidden("Account is not active".to_string()));
        }
        if let Some(locked_until) = identity.locked_until {
            if locked_until > Utc::now() {
                return Err(AppError::Locked("Account is temporarily locked".to_string()));
            }
        }
        if let Some(valid_until) = user.access_valid_until {
            if Utc::now() > valid_until {
                return Err(AppError::AccessExpired("Account access has expired".to_string()));
            }
        }
        Ok(())
    }

    /// Shared tail once the credential is verified and gates pass: force-change → MFA →
    /// session. Force-change and MFA are global (read off the identity).
    async fn finalize_login(
        &self,
        tenant_id: &str,
        user: &User,
        identity: &Identity,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LoginResult, AppError> {
        if identity.force_password_change {
            return self.issue_force_change_token(tenant_id, user.id).await;
        }
        if identity.mfa_enabled {
            return Ok(LoginResult::MfaRequired {
                mfa_token: Uuid::new_v4().to_string(),
                user_id: user.id,
            });
        }
        self.do_create_session(tenant_id, user, ip, user_agent).await
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
        let identity = self.load_identity(user.identity_id).await?;
        Self::check_gates(user, &identity)?;
        let effective = self.effective_login_methods(tenant_id, user.id, user).await?;
        if !effective.contains(&method) {
            return Err(AppError::Forbidden("This login method is not allowed for your account".to_string()));
        }
        // Credential lives on the identity (shared across tenants).
        let password_hash = identity
            .password_hash
            .as_ref()
            .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
        if !self.verify_password(password_hash, password)? {
            self.register_failed_attempt(&identity).await?;
            return Err(AppError::Unauthorized("Invalid email or password".to_string()));
        }
        self.identities_repo.clear_failed_attempts(identity.id).await?;
        self.finalize_login(tenant_id, user, &identity, ip, user_agent).await
    }

    /// Global lockout: failed attempts accrue against the shared credential, so they cannot
    /// be spread across tenants to bypass the lock.
    async fn register_failed_attempt(&self, identity: &Identity) -> Result<(), AppError> {
        let lock_until = if identity.failed_attempts + 1 >= DEFAULT_LOCK_AFTER_ATTEMPTS {
            Some(Utc::now() + Duration::minutes(DEFAULT_LOCK_DURATION_MINS))
        } else {
            None
        };
        self.identities_repo
            .increment_failed_attempts(identity.id, lock_until)
            .await
    }

    /// Create a session for a user (after password or OTP verified). Caller must have checked status, lock, and login method.
    async fn do_create_session(
        &self,
        tenant_id: &str,
        user: &User,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LoginResult, AppError> {
        let direct_role_uids = self.roles_repo.get_user_roles(tenant_id, user.id).await.unwrap_or_default();
        let direct_role_ids  = self.roles_repo.get_user_role_ids(tenant_id, user.id).await.unwrap_or_default();
        let direct_perms     = self.roles_repo.get_user_permissions(tenant_id, user.id).await.unwrap_or_default();

        let group_uids      = self.groups_repo.get_user_group_uids(tenant_id, user.id).await.unwrap_or_default();
        let group_ids       = self.groups_repo.get_user_group_ids(tenant_id, user.id).await.unwrap_or_default();
        let group_role_uids = self.groups_repo.get_user_group_role_uids(tenant_id, user.id).await.unwrap_or_default();
        let group_role_ids  = self.groups_repo.get_user_group_role_ids(tenant_id, user.id).await.unwrap_or_default();
        let group_perms     = self.groups_repo.get_user_group_permissions(tenant_id, user.id).await.unwrap_or_default();

        let roles = dedup_chain(direct_role_uids, group_role_uids);
        let role_ids = dedup_chain(direct_role_ids, group_role_ids);
        let permissions = dedup_chain(direct_perms, group_perms);

        let session_policy = self.tenant_config.get_session_policy(tenant_id).await?;
        let ttl_secs = session_policy
            .and_then(|p| p.absolute_timeout_mins)
            .map(|m| m * 60)
            .unwrap_or(self.default_session_ttl_secs);
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
        let session_token = generate_session_token();
        let payload = SessionPayload {
            tenant_id: tenant_id.to_string(),
            user_id: user.id,
            identity_id: user.identity_id,
            roles,
            role_ids,
            permissions,
            groups: group_uids,
            group_ids,
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
        let identity = self.load_identity(user.identity_id).await?;
        Self::check_gates(&user, &identity)?;
        let effective = self.effective_login_methods(tenant_id, user.id, &user).await?;
        if !effective.contains(&LOGIN_METHOD_EMAIL_OTP) {
            return Err(AppError::Forbidden("Email OTP login is not allowed for your account".to_string()));
        }
        self.finalize_login(tenant_id, &user, &identity, ip, user_agent).await
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
    ) -> Result<SignupOutcome, AppError> {
        let email = email.trim();
        if email.is_empty() {
            return Err(AppError::BadRequest("Email is required".to_string()));
        }
        self.ensure_email_domain_allowed(tenant_id, email).await?;
        if password != retype_password {
            return Err(AppError::BadRequest("Password and retype password do not match".to_string()));
        }
        let policy = self.tenant_config.get_password_policy(tenant_id).await?;
        Self::validate_password_policy(password, policy.as_ref())?;
        if let (Some(m), Some(c)) = (mobile, country_code) {
            if !m.trim().is_empty() && c.trim().is_empty() {
                return Err(AppError::BadRequest(
                    "Country code is required when mobile is provided".to_string(),
                ));
            }
        }
        let mobile = mobile.map(|s| s.trim()).filter(|s| !s.is_empty());
        let country_code = country_code.map(|s| s.trim()).filter(|s| !s.is_empty());
        let first = Some(first_name.trim()).filter(|s| !s.is_empty());
        let last = Some(last_name.trim()).filter(|s| !s.is_empty());

        // Already a member of THIS tenant with that email?
        if self.users_repo.get_by_email(tenant_id, email).await?.is_some() {
            return Err(AppError::Conflict("An account with this email already exists".to_string()));
        }

        // Public signup colliding with an EXISTING global identity: do not silently attach.
        // Email the real owner a verify-to-join link; the caller never learns the account
        // exists (returns the same VerificationSent outcome).
        let existing = match self.identities_repo.get_by_email(email).await? {
            Some(i) => Some(i),
            None => match (mobile, country_code) {
                (Some(m), Some(c)) => self.identities_repo.get_by_mobile(c, m).await?,
                _ => None,
            },
        };
        if let Some(identity) = existing {
            let token = generate_session_token();
            let expires_at = Utc::now() + Duration::minutes(PASSWORD_RESET_TOKEN_TTL_MINS);
            self.membership_invites_repo
                .create(identity.id, tenant_id, first, last, None, &token, expires_at)
                .await?;
            let to_email = identity.email.clone().unwrap_or_else(|| email.to_string());
            return Ok(SignupOutcome::VerificationSent { email: to_email, token });
        }

        // No collision: create the identity + membership.
        let password_hash = self.hash_password(password)?;
        let identity = self
            .identities_repo
            .create(Some(email), mobile, country_code, first, last, Some(&password_hash))
            .await?;
        let user = self.users_repo.create(&identity, tenant_id, None).await?;
        Ok(SignupOutcome::Created(user))
    }

    /// Accept a membership invite (verify-to-join). Creates the membership in the invited
    /// tenant for the already-existing identity. No X-Tenant-ID — the tenant is in the token.
    pub async fn verify_membership_invite(&self, token: &str) -> Result<User, AppError> {
        let invite = self
            .membership_invites_repo
            .get_valid(token)
            .await?
            .ok_or_else(|| AppError::BadRequest("Invalid or expired invite token".to_string()))?;
        // Idempotent: if the membership already exists, just consume the token.
        if let Some(user) = self
            .users_repo
            .get_membership(invite.identity_id, &invite.tenant_id)
            .await?
        {
            self.membership_invites_repo.delete_by_token(token).await?;
            return Ok(user);
        }
        let identity = self.load_identity(invite.identity_id).await?;
        let user = self
            .users_repo
            .create(&identity, &invite.tenant_id, invite.username.as_deref())
            .await?;
        self.membership_invites_repo.delete_by_token(token).await?;
        Ok(user)
    }

    /// Forgot password: create a reset token. Returns Some((email, token)) when user exists so caller can send email; None to avoid email enumeration.
    /// Forgot password resolves the GLOBAL identity by email (reset affects the one shared
    /// credential). `_tenant_id` is retained for the route signature but not used to scope.
    pub async fn forgot_password(
        &self,
        _tenant_id: &str,
        email: &str,
    ) -> Result<Option<(String, String)>, AppError> {
        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Err(AppError::BadRequest("Email is required".to_string()));
        }
        let identity = match self.identities_repo.get_by_email(&email).await? {
            Some(i) => i,
            None => return Ok(None),
        };
        let to_email = match &identity.email {
            Some(e) => e.clone(),
            None => return Ok(None),
        };
        self.password_reset_tokens_repo
            .delete_for_identity(identity.id)
            .await?;
        let token = generate_session_token();
        let expires_at = Utc::now() + Duration::minutes(PASSWORD_RESET_TOKEN_TTL_MINS);
        self.password_reset_tokens_repo
            .create(identity.id, &token, expires_at)
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
        // Password policy applies for the tenant the reset was requested under (X-Tenant-ID).
        let policy = self.tenant_config.get_password_policy(tenant_id).await?;
        Self::validate_password_policy(new_password, policy.as_ref())?;
        let identity_id = self
            .password_reset_tokens_repo
            .get_valid(token)
            .await?
            .ok_or_else(|| AppError::BadRequest("Invalid or expired reset token".to_string()))?;
        let password_hash = self.hash_password(new_password)?;
        self.identities_repo.update_password(identity_id, &password_hash).await?;
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
        let identity = self.load_identity(user.identity_id).await?;
        let password_hash = identity
            .password_hash
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("Account has no password set".to_string()))?;
        if !self.verify_password(password_hash, current_password)? {
            return Err(AppError::Unauthorized("Current password is incorrect".to_string()));
        }
        let new_hash = self.hash_password(new_password)?;
        self.identities_repo.update_password(identity.id, &new_hash).await?;
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
        // NOTE: this now sets the GLOBAL credential (all tenants). Phase 5e will restrict
        // admin reset to force-change-only so a tenant admin cannot set another tenant's
        // usable password.
        let user = self
            .users_repo
            .get_by_id(tenant_id, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
        // The credential is shared across every tenant this identity belongs to. A tenant
        // admin may set a usable password only when the identity is single-tenant (no
        // cross-tenant blast radius). For a multi-tenant identity, only force-change is
        // allowed — the user must reset the password themselves.
        let membership_count = self
            .users_repo
            .get_memberships_for_identity(user.identity_id)
            .await?
            .len();
        if membership_count > 1 {
            if !force_password_change {
                return Err(AppError::Forbidden(
                    "This account belongs to multiple tenants; you cannot set its shared password. Pass forcePasswordChange=true to require the user to reset it themselves.".to_string(),
                ));
            }
            self.identities_repo
                .set_force_password_change(user.identity_id, true)
                .await?;
        } else {
            let password_hash = self.hash_password(new_password)?;
            self.identities_repo.update_password(user.identity_id, &password_hash).await?;
            self.identities_repo
                .set_force_password_change(user.identity_id, force_password_change)
                .await?;
        }
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

        if let Some(valid_until) = user.access_valid_until {
            if Utc::now() > valid_until {
                return Err(AppError::AccessExpired("Account access has expired".to_string()));
            }
        }

        let password_hash = self.hash_password(new_password)?;
        // update_password also clears the global force_password_change flag.
        self.identities_repo.update_password(user.identity_id, &password_hash).await?;
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
        let first = first_name.map(|s| s.trim()).filter(|s| !s.is_empty());
        let last = last_name.map(|s| s.trim()).filter(|s| !s.is_empty());
        // Admin is trusted: attach to an existing global identity if the email/mobile maps
        // to one; otherwise create (handle-less if username-only).
        let identity = self
            .resolve_or_create_identity(email, mobile, country_code, first, last, password_hash.as_deref())
            .await?;
        let user = self.users_repo.create(&identity, tenant_id, username).await?;
        Ok(user)
    }

    /// Find a global identity by email or mobile, or create one. Used by the trusted admin
    /// provisioning path (attach-if-exists).
    async fn resolve_or_create_identity(
        &self,
        email: Option<&str>,
        mobile: Option<&str>,
        country_code: Option<&str>,
        first_name: Option<&str>,
        last_name: Option<&str>,
        password_hash: Option<&str>,
    ) -> Result<Identity, AppError> {
        if let Some(e) = email {
            if let Some(i) = self.identities_repo.get_by_email(e).await? {
                return Ok(i);
            }
        }
        if let (Some(m), Some(c)) = (mobile, country_code) {
            if let Some(i) = self.identities_repo.get_by_mobile(c, m).await? {
                return Ok(i);
            }
        }
        self.identities_repo
            .create(email, mobile, country_code, first_name, last_name, password_hash)
            .await
    }

    pub async fn admin_set_access_valid_until(
        &self,
        tenant_id: &str,
        user_id: Uuid,
        access_valid_until: Option<chrono::DateTime<Utc>>,
    ) -> Result<(), AppError> {
        let _user = self
            .users_repo
            .get_by_id(tenant_id, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
        self.users_repo
            .set_access_valid_until(tenant_id, user_id, access_valid_until)
            .await
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

    // ---- SSO: identity-first (tenant-less) login + tenant selection -------------------

    /// Tenant-less login by a global handle (email). Verifies the shared credential and
    /// global lockout, then returns the identity id and its tenant memberships. The route
    /// layer issues a short-lived identity token from this; tenant selection happens via
    /// `select_tenant`. (force-change / MFA are evaluated per-tenant at selection time.)
    pub async fn login_identity(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(String, Vec<TenantMembership>), AppError> {
        let email = email.trim();
        let identity = self
            .identities_repo
            .get_by_email(email)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
        if identity.status != "active" {
            return Err(AppError::Forbidden("Account is not active".to_string()));
        }
        if let Some(locked_until) = identity.locked_until {
            if locked_until > Utc::now() {
                return Err(AppError::Locked("Account is temporarily locked".to_string()));
            }
        }
        let password_hash = identity
            .password_hash
            .as_ref()
            .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
        if !self.verify_password(password_hash, password)? {
            self.register_failed_attempt(&identity).await?;
            return Err(AppError::Unauthorized("Invalid credentials".to_string()));
        }
        self.identities_repo.clear_failed_attempts(identity.id).await?;

        let identity_token = generate_session_token();
        let expires_at = Utc::now() + Duration::minutes(IDENTITY_TOKEN_TTL_MINS);
        self.identity_tokens_repo
            .create(identity.id, &identity_token, expires_at)
            .await?;
        let tenants = self.tenants_for_identity(identity.id).await?;
        Ok((identity_token, tenants))
    }

    /// Resolve an identity token to its tenant memberships (the SSO tenant picker).
    pub async fn tenants_for_identity_token(
        &self,
        identity_token: &str,
    ) -> Result<Vec<TenantMembership>, AppError> {
        let identity_id = self
            .identity_tokens_repo
            .get_valid(identity_token)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid or expired identity token".to_string()))?;
        self.tenants_for_identity(identity_id).await
    }

    /// The tenant memberships of an identity (for the SSO tenant picker / session switcher).
    pub async fn tenants_for_identity(&self, identity_id: Uuid) -> Result<Vec<TenantMembership>, AppError> {
        Ok(self
            .users_repo
            .get_memberships_for_identity(identity_id)
            .await?
            .into_iter()
            .map(|m| TenantMembership {
                tenant_id: m.tenant_id,
                status: m.status,
            })
            .collect())
    }

    /// Exchange an identity token for a tenant-scoped session (SSO select-tenant).
    pub async fn select_tenant_with_token(
        &self,
        identity_token: &str,
        tenant_id: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LoginResult, AppError> {
        let identity_id = self
            .identity_tokens_repo
            .get_valid(identity_token)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid or expired identity token".to_string()))?;
        self.select_tenant(identity_id, tenant_id, ip, user_agent).await
    }

    /// Mint a tenant-scoped session for an already-authenticated identity (SSO
    /// select-tenant and session-switch share this). Verifies the membership exists and
    /// passes the same gates / force-change / MFA tail as a direct login.
    pub async fn select_tenant(
        &self,
        identity_id: Uuid,
        tenant_id: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LoginResult, AppError> {
        let user = self
            .users_repo
            .get_membership(identity_id, tenant_id)
            .await?
            .ok_or_else(|| AppError::Forbidden("No membership in this tenant".to_string()))?;
        let identity = self.load_identity(identity_id).await?;
        Self::check_gates(&user, &identity)?;
        self.finalize_login(tenant_id, &user, &identity, ip, user_agent).await
    }
}

/// A tenant the identity belongs to, returned by `login_identity` for the SSO tenant picker.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantMembership {
    pub tenant_id: String,
    pub status: String,
}

/// Outcome of a public signup. A collision with an existing global identity yields
/// `VerificationSent` (an email goes to the real owner) rather than creating an account.
pub enum SignupOutcome {
    Created(User),
    VerificationSent { email: String, token: String },
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
