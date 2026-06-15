//! Membership repository. A `users` row is a per-tenant membership of a global identity
//! (`identity_id`). Display fields (name/email/mobile) and `mfa_enabled` live on the
//! `identities` row and are joined in for reads; the membership row itself holds only
//! `identity_id`, `username`, `status`, and `access_valid_until`.

use crate::domain::identity::Identity;
use crate::domain::user::User;
use crate::error::AppError;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Select list + join used by every membership read. `u` = users, `i` = identities.
const SELECT_COLS: &str = "u.id, u.tenant_id, u.identity_id, i.first_name, i.last_name, \
                           i.email, u.username, i.mobile, i.country_code, u.status, \
                           i.mfa_enabled, u.access_valid_until, u.created_at, u.updated_at";
const FROM_JOIN: &str = "FROM users u JOIN identities i ON i.id = u.identity_id";

#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    tenant_id: String,
    identity_id: Uuid,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    username: Option<String>,
    mobile: Option<String>,
    country_code: Option<String>,
    status: String,
    mfa_enabled: bool,
    access_valid_until: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct UsersRepo {
    pool: PgPool,
}

impl UsersRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_user(r: UserRow) -> User {
        User {
            id: r.id,
            tenant_id: r.tenant_id,
            identity_id: r.identity_id,
            first_name: r.first_name,
            last_name: r.last_name,
            email: r.email,
            username: r.username,
            mobile: r.mobile,
            country_code: r.country_code,
            status: r.status,
            mfa_enabled: r.mfa_enabled,
            access_valid_until: r.access_valid_until,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }

    /// Create a membership row linking an identity to a tenant. Display fields come from the
    /// identity; only `username` is per-tenant.
    pub async fn create(
        &self,
        identity: &Identity,
        tenant_id: &str,
        username: Option<&str>,
    ) -> Result<User, AppError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        sqlx::query(
            r#"INSERT INTO users (id, tenant_id, identity_id, username, status, created_at, updated_at)
               VALUES ($1, $2, $3, $4, 'active', $5, $5)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identity.id)
        .bind(username)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(User {
            id,
            tenant_id: tenant_id.to_string(),
            identity_id: identity.id,
            first_name: identity.first_name.clone(),
            last_name: identity.last_name.clone(),
            email: identity.email.clone(),
            username: username.map(String::from),
            mobile: identity.mobile.clone(),
            country_code: identity.country_code.clone(),
            status: "active".to_string(),
            mfa_enabled: identity.mfa_enabled,
            access_valid_until: None,
            created_at: now,
            updated_at: now,
        })
    }

    /// List memberships for a tenant (newest first). Excludes archived unless requested.
    pub async fn list(&self, tenant_id: &str, include_archived: bool) -> Result<Vec<User>, AppError> {
        let sql = if include_archived {
            format!("SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.tenant_id = $1 ORDER BY u.created_at DESC")
        } else {
            format!("SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.tenant_id = $1 AND u.status != 'archived' ORDER BY u.created_at DESC")
        };
        let rows = sqlx::query_as::<_, UserRow>(&sql)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(Self::row_to_user).collect())
    }

    pub async fn archive(&self, tenant_id: &str, user_id: Uuid) -> Result<bool, AppError> {
        let result = sqlx::query(
            "UPDATE users SET status = 'archived', updated_at = now() WHERE tenant_id = $1 AND id = $2 AND status != 'archived'",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_by_id(&self, tenant_id: &str, user_id: Uuid) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.tenant_id = $1 AND u.id = $2"
        ))
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    /// The single membership of an identity within a tenant (the SSO select-tenant path).
    pub async fn get_membership(
        &self,
        identity_id: Uuid,
        tenant_id: &str,
    ) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.identity_id = $1 AND u.tenant_id = $2"
        ))
        .bind(identity_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    /// All memberships of an identity across tenants (the identity's tenant list).
    pub async fn get_memberships_for_identity(&self, identity_id: Uuid) -> Result<Vec<User>, AppError> {
        let rows = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.identity_id = $1 AND u.status != 'archived' ORDER BY u.created_at"
        ))
        .bind(identity_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Self::row_to_user).collect())
    }

    /// Membership in a tenant whose identity has the given email (per-tenant existence check).
    pub async fn get_by_email(&self, tenant_id: &str, email: &str) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.tenant_id = $1 AND i.email = $2"
        ))
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    /// Case-insensitive variant. Used for OTP verify.
    pub async fn get_by_email_insensitive(&self, tenant_id: &str, email: &str) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.tenant_id = $1 AND LOWER(i.email) = LOWER($2)"
        ))
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    pub async fn get_by_username(&self, tenant_id: &str, username: &str) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.tenant_id = $1 AND u.username = $2"
        ))
        .bind(tenant_id)
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    pub async fn set_access_valid_until(
        &self,
        tenant_id: &str,
        user_id: Uuid,
        access_valid_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE users SET access_valid_until = $1, updated_at = now() WHERE tenant_id = $2 AND id = $3",
        )
        .bind(access_valid_until)
        .bind(tenant_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn exists_by_username(&self, tenant_id: &str, username: &str) -> Result<bool, AppError> {
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id = $1 AND username = $2)",
        )
        .bind(tenant_id)
        .bind(username)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }
}
