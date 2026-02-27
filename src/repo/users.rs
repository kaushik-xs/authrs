//! User repository.

use crate::domain::user::User;
use crate::error::AppError;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    tenant_id: String,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    username: Option<String>,
    mobile: Option<String>,
    country_code: Option<String>,
    password_hash: Option<String>,
    status: String,
    mfa_enabled: bool,
    failed_attempts: i32,
    locked_until: Option<chrono::DateTime<chrono::Utc>>,
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
            first_name: r.first_name,
            last_name: r.last_name,
            email: r.email,
            username: r.username,
            mobile: r.mobile,
            country_code: r.country_code,
            password_hash: r.password_hash,
            status: r.status,
            mfa_enabled: r.mfa_enabled,
            failed_attempts: r.failed_attempts,
            locked_until: r.locked_until,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }

    /// Create a new user. At least one of email, (mobile+country_code), or username must be set.
    pub async fn create(
        &self,
        tenant_id: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        email: Option<&str>,
        username: Option<&str>,
        mobile: Option<&str>,
        country_code: Option<&str>,
        password_hash: Option<&str>,
    ) -> Result<User, AppError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        sqlx::query(
            r#"INSERT INTO users (id, tenant_id, first_name, last_name, email, username, mobile, country_code, password_hash, status, mfa_enabled, failed_attempts, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', false, 0, $10, $10)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(first_name)
        .bind(last_name)
        .bind(email)
        .bind(username)
        .bind(mobile)
        .bind(country_code)
        .bind(password_hash)
        .bind(now)
        .execute(&self.pool)
        .await?;
        let user = User {
            id,
            tenant_id: tenant_id.to_string(),
            first_name: first_name.map(String::from),
            last_name: last_name.map(String::from),
            email: email.map(String::from),
            username: username.map(String::from),
            mobile: mobile.map(String::from),
            country_code: country_code.map(String::from),
            password_hash: password_hash.map(String::from),
            status: "active".to_string(),
            mfa_enabled: false,
            failed_attempts: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        };
        Ok(user)
    }

    pub async fn get_by_id(&self, tenant_id: &str, user_id: Uuid) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, tenant_id, first_name, last_name, email, username, mobile, country_code, password_hash, status, mfa_enabled, failed_attempts, locked_until, created_at, updated_at FROM users WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    pub async fn get_by_email(&self, tenant_id: &str, email: &str) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, tenant_id, first_name, last_name, email, username, mobile, country_code, password_hash, status, mfa_enabled, failed_attempts, locked_until, created_at, updated_at FROM users WHERE tenant_id = $1 AND email = $2",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    /// Look up user by email (case-insensitive). Used for OTP verify.
    pub async fn get_by_email_insensitive(&self, tenant_id: &str, email: &str) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, tenant_id, first_name, last_name, email, username, mobile, country_code, password_hash, status, mfa_enabled, failed_attempts, locked_until, created_at, updated_at FROM users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    pub async fn get_by_username(&self, tenant_id: &str, username: &str) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, tenant_id, first_name, last_name, email, username, mobile, country_code, password_hash, status, mfa_enabled, failed_attempts, locked_until, created_at, updated_at FROM users WHERE tenant_id = $1 AND username = $2",
        )
        .bind(tenant_id)
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    pub async fn increment_failed_attempts(
        &self,
        tenant_id: &str,
        user_id: Uuid,
        lock_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), AppError> {
        if let Some(until) = lock_until {
            sqlx::query(
                "UPDATE users SET failed_attempts = failed_attempts + 1, locked_until = $1, updated_at = now() WHERE tenant_id = $2 AND id = $3",
            )
            .bind(until)
            .bind(tenant_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE users SET failed_attempts = failed_attempts + 1, updated_at = now() WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn clear_failed_attempts(&self, tenant_id: &str, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = now() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update user's password hash (for change-password and reset-password flows).
    pub async fn update_password(
        &self,
        tenant_id: &str,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE users SET password_hash = $1, updated_at = now() WHERE tenant_id = $2 AND id = $3",
        )
        .bind(password_hash)
        .bind(tenant_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
