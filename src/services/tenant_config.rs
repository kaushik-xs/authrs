//! Tenant config loader: reads from kv_store with per-tenant caching.

use crate::repo::kv_store::{KvStoreRepo, KvValue};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const CACHE_TTL_SECS: u64 = 60;

struct CacheEntry {
    value: KvValue,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct TenantConfigLoader {
    repo: KvStoreRepo,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl TenantConfigLoader {
    pub fn new(repo: KvStoreRepo) -> Self {
        Self {
            repo,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn cache_key(tenant_id: &str, group_key: &str, key: &str) -> String {
        format!("{}:{}:{}", tenant_id, group_key, key)
    }

    pub async fn get(
        &self,
        tenant_id: &str,
        group_key: &str,
        key: &str,
    ) -> Result<Option<KvValue>, crate::error::AppError> {
        let ck = Self::cache_key(tenant_id, group_key, key);
        {
            let guard = self.cache.read().unwrap();
            if let Some(ent) = guard.get(&ck) {
                if ent.expires_at > Instant::now() {
                    return Ok(Some(ent.value.clone()));
                }
            }
        }
        let value = self.repo.get(tenant_id, group_key, key).await?;
        if let Some(ref v) = value {
            let mut guard = self.cache.write().unwrap();
            guard.insert(
                ck,
                CacheEntry {
                    value: v.clone(),
                    expires_at: Instant::now() + Duration::from_secs(CACHE_TTL_SECS),
                },
            );
        }
        Ok(value)
    }

    pub async fn get_oauth(&self, tenant_id: &str, provider: &str) -> Result<Option<OauthConfig>, crate::error::AppError> {
        let v = self.get(tenant_id, "oauth", provider).await?;
        Ok(v.and_then(|j| serde_json::from_value(j).ok()))
    }

    pub async fn get_password_policy(&self, tenant_id: &str) -> Result<Option<PasswordPolicy>, crate::error::AppError> {
        let v = self.get(tenant_id, "password_policy", "default").await?;
        Ok(v.and_then(|j| serde_json::from_value(j).ok()))
    }

    pub async fn get_session_policy(&self, tenant_id: &str) -> Result<Option<SessionPolicy>, crate::error::AppError> {
        let v = self.get(tenant_id, "session_policy", "default").await?;
        Ok(v.and_then(|j| serde_json::from_value(j).ok()))
    }

    pub async fn get_rate_limits(&self, tenant_id: &str, name: &str) -> Result<Option<RateLimitConfig>, crate::error::AppError> {
        let v = self.get(tenant_id, "rate_limits", name).await?;
        Ok(v.and_then(|j| serde_json::from_value(j).ok()))
    }

    pub async fn get_login_methods(&self, tenant_id: &str) -> Result<Option<Vec<i32>>, crate::error::AppError> {
        let v = self.get(tenant_id, "login_methods", "allowed").await?;
        Ok(v.and_then(|j| serde_json::from_value(j).ok()))
    }

    /// Per-tenant frontend base URL used to build links (e.g. password reset).
    /// Stored as a plain JSON string under group "frontend_config", key "base_url".
    pub async fn get_frontend_base_url(&self, tenant_id: &str) -> Result<Option<String>, crate::error::AppError> {
        let v = self.get(tenant_id, "frontend_config", "base_url").await?;
        Ok(v.and_then(|j| j.as_str().map(|s| s.to_string())).filter(|s| !s.is_empty()))
    }

    /// Invalidate cache for a tenant (e.g. after admin updates kv_store).
    pub fn invalidate_tenant(&self, tenant_id: &str) {
        let prefix = format!("{}:", tenant_id);
        let mut guard = self.cache.write().unwrap();
        guard.retain(|k, _| !k.starts_with(&prefix));
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordPolicy {
    pub min_length: Option<u32>,
    pub require_uppercase: Option<bool>,
    pub require_digit: Option<bool>,
    pub max_age_days: Option<u32>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPolicy {
    pub idle_timeout_mins: Option<u64>,
    pub absolute_timeout_mins: Option<u64>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitConfig {
    pub max_requests: Option<u32>,
    pub window_secs: Option<u64>,
}
