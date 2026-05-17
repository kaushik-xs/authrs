//! Password reset token repository.

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

    /// Create a reset token for the user. Returns the token string.
    pub async fn create(
        &self,
        tenant_id: &str,
        user_id: Uuid,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"INSERT INTO password_reset_tokens (tenant_id, user_id, token, expires_at)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(token)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find valid token and return (tenant_id, user_id). Returns None if not found or expired.
    pub async fn get_valid(
        &self,
        token: &str,
    ) -> Result<Option<(String, Uuid)>, AppError> {
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, (String, Uuid)>(
            "SELECT tenant_id, user_id FROM password_reset_tokens WHERE token = $1 AND expires_at > $2",
        )
        .bind(token)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Delete a token (after successful reset).
    pub async fn delete_by_token(&self, token: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM password_reset_tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Optionally invalidate any existing tokens for a user (e.g. when requesting a new reset).
    pub async fn delete_for_user(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query("DELETE FROM password_reset_tokens WHERE tenant_id = $1 AND user_id = $2")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
