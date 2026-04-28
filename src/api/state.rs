//! Application state shared across routes.

use crate::middleware::tenant::TenantState;
use crate::config::SmtpConfig;
use crate::repo::{
    force_change_tokens::ForceChangeTokensRepo,
    kv_store::KvStoreRepo,
    otp::OtpRepo,
    password_reset_tokens::PasswordResetTokensRepo,
    roles::RolesRepo,
    tenants::TenantsRepo,
    users::UsersRepo,
};
use crate::services::auth::AuthService;
use crate::services::tenant_config::TenantConfigLoader;
use crate::repo::sessions::PostgresSessionStore;
use crate::services::session::SessionStore;
use std::sync::Arc;

/// Full app state for routes that need DB, session store, auth, etc.
#[derive(Clone)]
pub struct AppState {
    pub tenant_state: TenantState,
    pub auth_service: AuthService,
    pub session_store: Arc<dyn SessionStore>,
    /// Used for audit revoke on logout (and as SessionStore when Redis disabled).
    pub sessions_repo: PostgresSessionStore,
    pub otp_repo: OtpRepo,
    /// SMTP for sending OTP emails; None if email OTP is disabled.
    pub smtp_config: Option<SmtpConfig>,
}

impl AppState {
    pub fn new(
        pool: sqlx::PgPool,
        kv_encryption_key: Option<String>,
        redis_url: Option<String>,
        smtp_config: Option<SmtpConfig>,
    ) -> Result<Self, crate::error::AppError> {
        let kv_store = KvStoreRepo::new(pool.clone(), kv_encryption_key)?;
        let tenant_config = TenantConfigLoader::new(kv_store);
        let tenants_repo = TenantsRepo::new(pool.clone());
        let tenant_state = TenantState {
            tenants_repo,
            tenant_config: tenant_config.clone(),
        };
        let users_repo = UsersRepo::new(pool.clone());
        let roles_repo = RolesRepo::new(pool.clone());
        let password_reset_tokens_repo = PasswordResetTokensRepo::new(pool.clone());
        let force_change_tokens_repo = ForceChangeTokensRepo::new(pool.clone());
        let sessions_repo = PostgresSessionStore::new(pool.clone());
        let session_store: Arc<dyn SessionStore> = if let Some(ref url) = redis_url {
            Arc::new(crate::repo::sessions_redis::RedisSessionStore::new(url)?)
        } else {
            Arc::new(sessions_repo.clone())
        };
        let auth_service = AuthService::new(
            users_repo,
            roles_repo,
            password_reset_tokens_repo,
            force_change_tokens_repo,
            tenant_config,
            session_store.clone(),
            sessions_repo.clone(),
        );
        let otp_repo = OtpRepo::new(pool.clone());
        Ok(Self {
            tenant_state,
            auth_service,
            session_store,
            sessions_repo,
            otp_repo,
            smtp_config,
        })
    }
}
