//! Redis session store implementation.

use crate::domain::session::SessionPayload;
use async_trait::async_trait;
use redis::AsyncCommands;
use serde_json;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::AppError;
use crate::services::session::SessionStore;

const SESSION_KEY_PREFIX: &str = "session:";
const USER_SESSIONS_PREFIX: &str = "user_sessions:";

pub struct RedisSessionStore {
    client: Arc<redis::Client>,
}

impl RedisSessionStore {
    pub fn new(redis_url: &str) -> Result<Self, AppError> {
        let client = redis::Client::open(redis_url).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(Self {
            client: Arc::new(client),
        })
    }

    fn key(session_token: &str) -> String {
        format!("{}{}", SESSION_KEY_PREFIX, session_token)
    }

    fn user_set_key(tenant_id: &str, user_id: Uuid) -> String {
        format!("{}{}:{}", USER_SESSIONS_PREFIX, tenant_id, user_id)
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn get(&self, session_token: &str) -> Result<Option<SessionPayload>, AppError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let key = Self::key(session_token);
        let raw: Option<String> = conn.get(&key).await.map_err(|e| AppError::Internal(e.to_string()))?;
        let payload = raw
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .map(|p: SessionPayload| p);
        Ok(payload)
    }

    async fn set(
        &self,
        session_token: &str,
        payload: &SessionPayload,
        ttl_secs: u64,
    ) -> Result<(), AppError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let key = Self::key(session_token);
        let json = serde_json::to_string(payload).map_err(|e| AppError::Internal(e.to_string()))?;
        conn.set_ex::<_, _, ()>(&key, &json, ttl_secs)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let user_key = Self::user_set_key(&payload.tenant_id, payload.user_id);
        conn.sadd::<_, _, ()>(&user_key, session_token)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        conn.expire::<_, ()>(&user_key, (ttl_secs + 86400) as i64)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, session_token: &str) -> Result<bool, AppError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let key = Self::key(session_token);
        let n: i32 = conn.del(&key).await.map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(n > 0)
    }

    async fn delete_all_for_user(&self, tenant_id: &str, user_id: Uuid) -> Result<u64, AppError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let user_key = Self::user_set_key(tenant_id, user_id);
        let session_tokens: Vec<String> = conn
            .smembers(&user_key)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let mut deleted = 0u64;
        for token in &session_tokens {
            let k = Self::key(token);
            let _: () = conn.del(&k).await.map_err(|e| AppError::Internal(e.to_string()))?;
            deleted += 1;
        }
        let _: () = conn.del(&user_key).await.map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(deleted)
    }
}
