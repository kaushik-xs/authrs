//! Identity token repository — short-lived tokens bridging tenant-less SSO login and
//! tenant selection. Keyed by identity; reusable until expiry.

use crate::error::AppError;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct IdentityTokensRepo {
    pool: PgPool,
}

impl IdentityTokensRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        identity_id: Uuid,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"INSERT INTO identity_tokens (identity_id, token, expires_at) VALUES ($1, $2, $3)"#,
        )
        .bind(identity_id)
        .bind(token)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Resolve a valid (non-expired) token to its identity_id.
    pub async fn get_valid(&self, token: &str) -> Result<Option<Uuid>, AppError> {
        let row = sqlx::query_as::<_, (Uuid,)>(
            "SELECT identity_id FROM identity_tokens WHERE token = $1 AND expires_at > now()",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.0))
    }

    pub async fn delete_by_token(&self, token: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM identity_tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
