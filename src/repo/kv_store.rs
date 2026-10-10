//! KV store repository: get/set/delete by tenant_id, group_key, key.
//! When sensitive = true, value is encrypted at rest (AES-256-GCM).

use crate::crypto::SecretCipher;
use crate::error::AppError;
use sqlx::{FromRow, PgPool};

/// Raw row from DB (value may be encrypted).
#[derive(Debug, FromRow)]
pub struct KvStoreRow {
    pub tenant_id: String,
    pub group_key: String,
    pub key: String,
    pub value: String,
    pub sensitive: bool,
}

/// Decrypted/plain value for callers.
pub type KvValue = serde_json::Value;

#[derive(Clone)]
pub struct KvStoreRepo {
    pool: PgPool,
    cipher: SecretCipher,
}

impl KvStoreRepo {
    pub fn new(pool: PgPool, encryption_key_base64: Option<String>) -> Result<Self, AppError> {
        let cipher = SecretCipher::new(encryption_key_base64.as_deref());
        Ok(Self { pool, cipher })
    }

    fn encrypt(&self, plain: &str) -> Result<String, AppError> {
        self.cipher.encrypt(plain)
    }

    fn decrypt(&self, encrypted_b64: &str) -> Result<String, AppError> {
        self.cipher.decrypt(encrypted_b64)
    }

    pub async fn get(
        &self,
        tenant_id: &str,
        group_key: &str,
        key: &str,
    ) -> Result<Option<KvValue>, AppError> {
        let row = sqlx::query_as::<_, KvStoreRow>(
            "SELECT tenant_id, group_key, key, value, sensitive FROM kv_store WHERE tenant_id = $1 AND group_key = $2 AND key = $3",
        )
        .bind(tenant_id)
        .bind(group_key)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        let value_str = if row.sensitive {
            self.decrypt(&row.value)?
        } else {
            row.value
        };
        let value: KvValue = serde_json::from_str(&value_str)
            .map_err(|e| AppError::Internal(format!("Invalid JSON in kv_store: {}", e)))?;
        Ok(Some(value))
    }

    pub async fn set(
        &self,
        tenant_id: &str,
        group_key: &str,
        key: &str,
        value: &KvValue,
        sensitive: bool,
    ) -> Result<(), AppError> {
        let value_str = serde_json::to_string(value).map_err(|e| AppError::Internal(e.to_string()))?;
        let stored = if sensitive {
            self.encrypt(&value_str)?
        } else {
            value_str
        };

        sqlx::query(
            r#"
            INSERT INTO kv_store (tenant_id, group_key, key, value, sensitive, updated_at)
            VALUES ($1, $2, $3, $4, $5, now())
            ON CONFLICT (tenant_id, group_key, key)
            DO UPDATE SET value = $4, sensitive = $5, updated_at = now()
            "#,
        )
        .bind(tenant_id)
        .bind(group_key)
        .bind(key)
        .bind(&stored)
        .bind(sensitive)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, tenant_id: &str, group_key: &str, key: &str) -> Result<bool, AppError> {
        let r = sqlx::query(
            "DELETE FROM kv_store WHERE tenant_id = $1 AND group_key = $2 AND key = $3",
        )
        .bind(tenant_id)
        .bind(group_key)
        .bind(key)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn list(
        &self,
        tenant_id: &str,
        group_key_filter: Option<&str>,
        key_filter: Option<&str>,
    ) -> Result<Vec<(String, String, bool)>, AppError> {
        let rows = if let Some(gk) = group_key_filter {
            if let Some(k) = key_filter {
                sqlx::query_as::<_, KvStoreRow>(
                    "SELECT tenant_id, group_key, key, value, sensitive FROM kv_store WHERE tenant_id = $1 AND group_key = $2 AND key = $3",
                )
                .bind(tenant_id)
                .bind(gk)
                .bind(k)
            } else {
                sqlx::query_as::<_, KvStoreRow>(
                    "SELECT tenant_id, group_key, key, value, sensitive FROM kv_store WHERE tenant_id = $1 AND group_key = $2",
                )
                .bind(tenant_id)
                .bind(gk)
            }
        } else {
            sqlx::query_as::<_, KvStoreRow>(
                "SELECT tenant_id, group_key, key, value, sensitive FROM kv_store WHERE tenant_id = $1",
            )
            .bind(tenant_id)
        }
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.group_key, r.key, r.sensitive))
            .collect())
    }
}
