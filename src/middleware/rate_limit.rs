//! Rate limit store implementations: Redis and in-memory.
//! Used by rate_limit middleware; trait is in services::rate_limit.

use crate::services::rate_limit::RateLimitStore;
use async_trait::async_trait;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::error::AppError;

/// Redis-based rate limiter (sliding window or fixed window via INCR + EXPIRE).
pub struct RedisRateLimitStore {
    client: std::sync::Arc<redis::Client>,
}

impl RedisRateLimitStore {
    pub fn new(redis_url: &str) -> Result<Self, AppError> {
        let client = redis::Client::open(redis_url).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(Self {
            client: std::sync::Arc::new(client),
        })
    }
}

#[async_trait]
impl RateLimitStore for RedisRateLimitStore {
    async fn check(&self, key: &str, limit: u32, window_secs: u64) -> Result<bool, AppError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let redis_key = format!("ratelimit:{}", key);
        let count: u32 = conn.incr(&redis_key, 1).await.map_err(|e| AppError::Internal(e.to_string()))?;
        if count == 1 {
            let _: () = conn
                .expire(&redis_key, window_secs as i64)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;
        }
        Ok(count <= limit)
    }
}

struct Window {
    count: u32,
    window_end: Instant,
}

/// In-memory rate limiter (per process; limits are per-instance when Redis is not used).
pub struct InMemoryRateLimitStore {
    store: RwLock<HashMap<String, Window>>,
}

impl InMemoryRateLimitStore {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl RateLimitStore for InMemoryRateLimitStore {
    async fn check(&self, key: &str, limit: u32, window_secs: u64) -> Result<bool, AppError> {
        let now = Instant::now();
        let window_duration = Duration::from_secs(window_secs);
        let mut guard = self.store.write().unwrap();
        let entry = guard.get_mut(key);
        let allowed = match entry {
            Some(w) => {
                if now >= w.window_end {
                    w.count = 1;
                    w.window_end = now + window_duration;
                    true
                } else {
                    w.count += 1;
                    w.count <= limit
                }
            }
            None => {
                guard.insert(
                    key.to_string(),
                    Window {
                        count: 1,
                        window_end: now + window_duration,
                    },
                );
                true
            }
        };
        Ok(allowed)
    }
}

impl Default for InMemoryRateLimitStore {
    fn default() -> Self {
        Self::new()
    }
}
