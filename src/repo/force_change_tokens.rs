//! Force-change-password token repository.

use crate::error::AppError;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct ForceChangeTokensRepo {
    pool: PgPool,
}

impl ForceChangeTokensRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Store a force-change token for the user. Any existing tokens for the user are replaced.
    pub async fn create(
        &self,
        tenant_id: &str,
        user_id: Uuid,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        sqlx::query(
            "DELETE FROM auth.force_change_tokens WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"INSERT INTO auth.force_change_tokens (tenant_id, user_id, token, expires_at)
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

    /// Find a valid (non-expired) token and return (tenant_id, user_id). Returns None if missing or expired.
    pub async fn get_valid(&self, token: &str) -> Result<Option<(String, Uuid)>, AppError> {
        let row = sqlx::query_as::<_, (String, Uuid)>(
            "SELECT tenant_id, user_id FROM auth.force_change_tokens WHERE token = $1 AND expires_at > now()",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Delete a token after it has been consumed.
    pub async fn delete_by_token(&self, token: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM auth.force_change_tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
