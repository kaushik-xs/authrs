//! Membership invite repository. Bridges public-signup collisions to a verified
//! join: a token bound to (identity, target tenant) that, when accepted, creates the
//! membership.

use crate::error::AppError;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(FromRow)]
pub struct MembershipInvite {
    pub identity_id: Uuid,
    pub tenant_id: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub username: Option<String>,
}

#[derive(Clone)]
pub struct MembershipInvitesRepo {
    pool: PgPool,
}

impl MembershipInvitesRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        identity_id: Uuid,
        tenant_id: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        username: Option<&str>,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        // One pending invite per (identity, tenant).
        sqlx::query("DELETE FROM membership_invites WHERE identity_id = $1 AND tenant_id = $2")
            .bind(identity_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"INSERT INTO membership_invites (identity_id, tenant_id, first_name, last_name, username, token, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(identity_id)
        .bind(tenant_id)
        .bind(first_name)
        .bind(last_name)
        .bind(username)
        .bind(token)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_valid(&self, token: &str) -> Result<Option<MembershipInvite>, AppError> {
        let row = sqlx::query_as::<_, MembershipInvite>(
            "SELECT identity_id, tenant_id, first_name, last_name, username FROM membership_invites WHERE token = $1 AND expires_at > now()",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_by_token(&self, token: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM membership_invites WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
