//! Rate limit store trait and implementations (Redis or in-memory).

use async_trait::async_trait;

#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Check and consume one slot for the key within the window. Returns true if allowed, false if rate limited.
    async fn check(&self, key: &str, limit: u32, window_secs: u64) -> Result<bool, crate::error::AppError>;
}
