//! Sessions (audit) and Postgres session store.

use crate::domain::session::SessionPayload;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppError;
use crate::services::session::SessionStore;

#[derive(Clone)]
pub struct PostgresSessionStore {
    pool: PgPool,
}

impl PostgresSessionStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert audit row and optionally store payload (for Postgres-as-store mode).
    pub async fn create_audit(
        &self,
        session_token: &str,
        tenant_id: &str,
        user_id: Uuid,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        expires_at: chrono::DateTime<Utc>,
        payload_json: Option<&str>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO sessions (tenant_id, user_id, session_token, ip_address, user_agent, expires_at, revoked, payload)
            VALUES ($1, $2, $3, $4, $5, $6, false, $7::jsonb)
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(session_token)
        .bind(ip_address)
        .bind(user_agent)
        .bind(expires_at)
        .bind(payload_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn revoke_by_session_token(&self, session_token: &str) -> Result<bool, AppError> {
        let r = sqlx::query(
            "UPDATE sessions SET revoked = true WHERE session_token = $1",
        )
        .bind(session_token)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn revoke_all_for_user(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<u64, AppError> {
        let r = sqlx::query(
            "UPDATE sessions SET revoked = true WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected())
    }
}

#[async_trait]
impl SessionStore for PostgresSessionStore {
    async fn get(&self, session_token: &str) -> Result<Option<SessionPayload>, AppError> {
        let row = sqlx::query_as::<_, (Option<String>,)>(
            "SELECT payload::text FROM sessions WHERE session_token = $1 AND revoked = false AND expires_at > now()",
        )
        .bind(session_token)
        .fetch_optional(&self.pool)
        .await?;

        let Some((Some(json),)) = row else {
            return Ok(None);
        };
        let payload: SessionPayload = serde_json::from_str(&json)
            .map_err(|e| AppError::Internal(format!("Invalid session payload: {}", e)))?;
        Ok(Some(payload))
    }

    async fn set(
        &self,
        session_token: &str,
        payload: &SessionPayload,
        _ttl_secs: u64,
    ) -> Result<(), AppError> {
        let json = serde_json::to_string(payload).map_err(|e| AppError::Internal(e.to_string()))?;
        self.create_audit(
            session_token,
            &payload.tenant_id,
            payload.user_id,
            payload.ip.as_deref(),
            payload.user_agent.as_deref(),
            payload.expires_at,
            Some(&json),
        )
        .await
    }

    async fn delete(&self, session_token: &str) -> Result<bool, AppError> {
        self.revoke_by_session_token(session_token).await
    }

    async fn delete_all_for_user(&self, tenant_id: &str, user_id: Uuid) -> Result<u64, AppError> {
        self.revoke_all_for_user(tenant_id, user_id).await
    }

    fn writes_audit_row(&self) -> bool {
        true
    }
}
