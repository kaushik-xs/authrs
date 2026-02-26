//! Session store trait and implementations (Redis or PostgreSQL).

use crate::domain::session::SessionPayload;
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn get(&self, session_token: &str) -> Result<Option<SessionPayload>, crate::error::AppError>;
    async fn set(
        &self,
        session_token: &str,
        payload: &SessionPayload,
        ttl_secs: u64,
    ) -> Result<(), crate::error::AppError>;
    async fn delete(&self, session_token: &str) -> Result<bool, crate::error::AppError>;
    async fn delete_all_for_user(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<u64, crate::error::AppError>;

    /// If true, `set()` already wrote the session to the audit table (e.g. Postgres store).
    /// If false, the caller must call `sessions_repo.create_audit()` after `set()` (e.g. Redis store).
    fn writes_audit_row(&self) -> bool {
        false
    }
}
