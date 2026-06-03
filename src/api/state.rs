//! Application state shared across routes.

use cedar_policy::Schema;
use std::sync::{Arc, RwLock};

use crate::config::SmtpConfig;
use crate::middleware::tenant::TenantState;
use crate::policy::schema::{build_schema_str, parse_schema};
use crate::repo::{
    force_change_tokens::ForceChangeTokensRepo,
    groups::GroupsRepo,
    kv_store::KvStoreRepo,
    otp::OtpRepo,
    packages::PackagesRepo,
    password_reset_tokens::PasswordResetTokensRepo,
    permissions::PermissionsRepo,
    roles::RolesRepo,
    sessions::PostgresSessionStore,
    tenants::TenantsRepo,
    users::UsersRepo,
};
use crate::services::auth::AuthService;
use crate::services::packages::PackagesService;
use crate::services::permissions::PermissionsService;
use crate::services::session::SessionStore;
use crate::services::tenant_config::TenantConfigLoader;

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
    /// Global fallback base URL for building links (e.g. password reset). Per-tenant
    /// config takes precedence; None disables link-building (falls back to raw token).
    pub frontend_url: Option<String>,
    pub permissions_service: PermissionsService,
    pub packages_service: PackagesService,
    pub cedar_schema: Arc<RwLock<Schema>>,
}

impl AppState {
    pub fn new(
        pool: sqlx::PgPool,
        kv_encryption_key: Option<String>,
        redis_url: Option<String>,
        smtp_config: Option<SmtpConfig>,
        frontend_url: Option<String>,
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
        let groups_repo = GroupsRepo::new(pool.clone());
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
            groups_repo,
            password_reset_tokens_repo,
            force_change_tokens_repo,
            tenant_config,
            session_store.clone(),
            sessions_repo.clone(),
        );
        let otp_repo = OtpRepo::new(pool.clone());

        // Cedar: start with an empty schema — PackagesService::rebuild_schema() is called
        // at server startup after migrations run to load registered packages from DB.
        let empty_schema = parse_schema(&build_schema_str(&[], &[]))
            .map_err(|e| crate::error::AppError::Internal(format!("Cedar schema init: {e}")))?;
        let cedar_schema = Arc::new(RwLock::new(empty_schema));

        let permissions_service = PermissionsService::new(PermissionsRepo::new(pool.clone()));

        let packages_service = PackagesService::new(
            PackagesRepo::new(pool.clone()),
            Arc::clone(&cedar_schema),
            permissions_service.clone(),
        );

        Ok(Self {
            tenant_state,
            auth_service,
            session_store,
            sessions_repo,
            otp_repo,
            smtp_config,
            frontend_url,
            permissions_service,
            packages_service,
            cedar_schema,
        })
    }
}
