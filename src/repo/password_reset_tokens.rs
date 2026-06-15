//! Password reset token repository. Reset is a global identity operation (one shared
//! credential), so tokens are keyed by identity_id. Legacy user_id/tenant_id columns are
//! retained-but-nullable until Phase 6 and are not written by new tokens.

use crate::error::AppError;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct PasswordResetTokensRepo {
    pool: PgPool,
}

impl PasswordResetTokensRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a reset token for an identity.
    pub async fn create(
        &self,
        identity_id: Uuid,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"INSERT INTO password_reset_tokens (identity_id, token, expires_at)
               VALUES ($1, $2, $3)"#,
        )
        .bind(identity_id)
        .bind(token)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find a valid token and return its identity_id. None if not found or expired.
    pub async fn get_valid(&self, token: &str) -> Result<Option<Uuid>, AppError> {
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, (Uuid,)>(
            "SELECT identity_id FROM password_reset_tokens WHERE token = $1 AND expires_at > $2",
        )
        .bind(token)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.0))
    }

    /// Delete a token (after successful reset).
    pub async fn delete_by_token(&self, token: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM password_reset_tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Invalidate any existing tokens for an identity (e.g. when requesting a new reset).
    pub async fn delete_for_identity(&self, identity_id: Uuid) -> Result<(), AppError> {
        sqlx::query("DELETE FROM password_reset_tokens WHERE identity_id = $1")
            .bind(identity_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
