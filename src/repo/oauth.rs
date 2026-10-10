//! OAuth repository — pending authorization states (single-use) and the links between
//! provider accounts and global identities (`identity_oauth_accounts`).

use crate::error::AppError;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A pending authorization request, created at redirect time and consumed at callback.
#[derive(Debug, FromRow)]
pub struct OauthState {
    pub tenant_id: String,
    pub provider: String,
    pub pkce_verifier: String,
    pub nonce: String,
}

#[derive(Clone)]
pub struct OauthRepo {
    pool: PgPool,
}

impl OauthRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_state(
        &self,
        state: &str,
        tenant_id: &str,
        provider: &str,
        pkce_verifier: &str,
        nonce: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        // Opportunistic cleanup keeps the table small without a background job.
        sqlx::query("DELETE FROM oauth_states WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"INSERT INTO oauth_states (state, tenant_id, provider, pkce_verifier, nonce, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(state)
        .bind(tenant_id)
        .bind(provider)
        .bind(pkce_verifier)
        .bind(nonce)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically consume a valid (non-expired) state. A state can be redeemed once.
    pub async fn take_state(&self, state: &str) -> Result<Option<OauthState>, AppError> {
        let row = sqlx::query_as::<_, OauthState>(
            r#"DELETE FROM oauth_states WHERE state = $1 AND expires_at > now()
               RETURNING tenant_id, provider, pkce_verifier, nonce"#,
        )
        .bind(state)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// The identity linked to a provider account, if any.
    pub async fn get_linked_identity(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<Uuid>, AppError> {
        let row = sqlx::query_as::<_, (Uuid,)>(
            "SELECT identity_id FROM identity_oauth_accounts WHERE provider = $1 AND provider_user_id = $2",
        )
        .bind(provider)
        .bind(provider_user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.0))
    }

    pub async fn link(
        &self,
        identity_id: Uuid,
        provider: &str,
        provider_user_id: &str,
        email: Option<&str>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"INSERT INTO identity_oauth_accounts (identity_id, provider, provider_user_id, email)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(identity_id)
        .bind(provider)
        .bind(provider_user_id)
        .bind(email)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
