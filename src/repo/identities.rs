//! Identity repository — global (cross-tenant) lookups and credential mutations.
//!
//! Unlike `UsersRepo` (per-tenant membership), every method here is tenant-agnostic:
//! identities are keyed by global handles (case-insensitive email, country_code+mobile)
//! and hold the shared credential, MFA, and lockout state.

use crate::domain::identity::Identity;
use crate::error::AppError;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

const COLS: &str = "id, email, mobile, country_code, first_name, last_name, password_hash, \
                    mfa_enabled, mfa_secret, force_password_change, failed_attempts, \
                    locked_until, status, created_at, updated_at";

#[derive(FromRow)]
struct IdentityRow {
    id: Uuid,
    email: Option<String>,
    mobile: Option<String>,
    country_code: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    password_hash: Option<String>,
    mfa_enabled: bool,
    mfa_secret: Option<String>,
    force_password_change: bool,
    failed_attempts: i32,
    locked_until: Option<chrono::DateTime<chrono::Utc>>,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct IdentitiesRepo {
    pool: PgPool,
}

impl IdentitiesRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_identity(r: IdentityRow) -> Identity {
        Identity {
            id: r.id,
            email: r.email,
            mobile: r.mobile,
            country_code: r.country_code,
            first_name: r.first_name,
            last_name: r.last_name,
            password_hash: r.password_hash,
            mfa_enabled: r.mfa_enabled,
            mfa_secret: r.mfa_secret,
            force_password_change: r.force_password_change,
            failed_attempts: r.failed_attempts,
            locked_until: r.locked_until,
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<Identity>, AppError> {
        let row = sqlx::query_as::<_, IdentityRow>(&format!(
            "SELECT {COLS} FROM identities WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_identity))
    }

    /// Global, case-insensitive email lookup (the SSO login path).
    pub async fn get_by_email(&self, email: &str) -> Result<Option<Identity>, AppError> {
        let row = sqlx::query_as::<_, IdentityRow>(&format!(
            "SELECT {COLS} FROM identities WHERE LOWER(email) = LOWER($1)"
        ))
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_identity))
    }

    /// Global mobile lookup (country_code + number together identify the phone).
    pub async fn get_by_mobile(
        &self,
        country_code: &str,
        mobile: &str,
    ) -> Result<Option<Identity>, AppError> {
        let row = sqlx::query_as::<_, IdentityRow>(&format!(
            "SELECT {COLS} FROM identities WHERE country_code = $1 AND mobile = $2"
        ))
        .bind(country_code)
        .bind(mobile)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_identity))
    }

    /// Create an identity. Any subset of handles may be set (all NULL = a username-only
    /// local identity, whose loginability comes from a membership username).
    pub async fn create(
        &self,
        email: Option<&str>,
        mobile: Option<&str>,
        country_code: Option<&str>,
        first_name: Option<&str>,
        last_name: Option<&str>,
        password_hash: Option<&str>,
    ) -> Result<Identity, AppError> {
        let row = sqlx::query_as::<_, IdentityRow>(&format!(
            "INSERT INTO identities (email, mobile, country_code, first_name, last_name, password_hash) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING {COLS}"
        ))
        .bind(email)
        .bind(mobile)
        .bind(country_code)
        .bind(first_name)
        .bind(last_name)
        .bind(password_hash)
        .fetch_one(&self.pool)
        .await?;
        Ok(Self::row_to_identity(row))
    }

    /// Set the shared password hash and clear the force-change flag (used after a
    /// successful reset / change).
    pub async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE identities SET password_hash = $1, force_password_change = false, updated_at = now() WHERE id = $2",
        )
        .bind(password_hash)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_force_password_change(&self, id: Uuid, value: bool) -> Result<(), AppError> {
        sqlx::query("UPDATE identities SET force_password_change = $1, updated_at = now() WHERE id = $2")
            .bind(value)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Global lockout — failed attempts accrue against the shared credential so they
    /// cannot be spread across tenants to bypass the lock.
    pub async fn increment_failed_attempts(
        &self,
        id: Uuid,
        lock_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), AppError> {
        if let Some(until) = lock_until {
            sqlx::query(
                "UPDATE identities SET failed_attempts = failed_attempts + 1, locked_until = $1, updated_at = now() WHERE id = $2",
            )
            .bind(until)
            .bind(id)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE identities SET failed_attempts = failed_attempts + 1, updated_at = now() WHERE id = $1",
            )
            .bind(id)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn clear_failed_attempts(&self, id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE identities SET failed_attempts = 0, locked_until = NULL, updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Global account kill-switch (distinct from per-tenant membership status).
    pub async fn set_status(&self, id: Uuid, status: &str) -> Result<(), AppError> {
        sqlx::query("UPDATE identities SET status = $1, updated_at = now() WHERE id = $2")
            .bind(status)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn exists_by_email(&self, email: &str) -> Result<bool, AppError> {
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM identities WHERE LOWER(email) = LOWER($1))",
        )
        .bind(email)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    pub async fn exists_by_mobile(
        &self,
        country_code: &str,
        mobile: &str,
    ) -> Result<bool, AppError> {
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM identities WHERE country_code = $1 AND mobile = $2)",
        )
        .bind(country_code)
        .bind(mobile)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }
}
