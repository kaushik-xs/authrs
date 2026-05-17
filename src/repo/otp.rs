//! OTP codes repository (otp_codes).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug)]
pub struct OtpRow {
    pub id: Uuid,
    pub tenant_id: String,
    pub identifier: String,
    pub channel: String,
    pub code: String,
    pub purpose: String,
    pub expires_at: DateTime<Utc>,
    pub attempt_count: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct OtpRepo {
    pool: PgPool,
}

impl OtpRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new OTP code. Identifier is email for channel=email.
    pub async fn create(
        &self,
        tenant_id: &str,
        identifier: &str,
        channel: &str,
        code: &str,
        purpose: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO otp_codes (id, tenant_id, identifier, channel, code, purpose, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identifier)
        .bind(channel)
        .bind(code)
        .bind(purpose)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Fetch the latest valid OTP for verify (not expired, same tenant/identifier/channel/purpose).
    /// For channel=email, identifier is matched case-insensitively.
    pub async fn get_latest(
        &self,
        tenant_id: &str,
        identifier: &str,
        channel: &str,
        purpose: &str,
    ) -> Result<Option<OtpRow>, sqlx::Error> {
        let row = if channel == "email" {
            sqlx::query_as::<_, (Uuid, String, String, String, String, String, DateTime<Utc>, i32, DateTime<Utc>)>(
                r#"
                SELECT id, tenant_id, identifier, channel, code, purpose, expires_at, attempt_count, created_at
                FROM otp_codes
                WHERE tenant_id = $1 AND LOWER(identifier) = LOWER($2) AND channel = $3 AND purpose = $4 AND expires_at > now()
                ORDER BY created_at DESC
                LIMIT 1
                "#,
            )
            .bind(tenant_id)
            .bind(identifier)
            .bind(channel)
            .bind(purpose)
        } else {
            sqlx::query_as::<_, (Uuid, String, String, String, String, String, DateTime<Utc>, i32, DateTime<Utc>)>(
                r#"
                SELECT id, tenant_id, identifier, channel, code, purpose, expires_at, attempt_count, created_at
                FROM otp_codes
                WHERE tenant_id = $1 AND identifier = $2 AND channel = $3 AND purpose = $4 AND expires_at > now()
                ORDER BY created_at DESC
                LIMIT 1
                "#,
            )
            .bind(tenant_id)
            .bind(identifier)
            .bind(channel)
            .bind(purpose)
        }
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(id, tenant_id, identifier, channel, code, purpose, expires_at, attempt_count, created_at)| OtpRow {
                id,
                tenant_id,
                identifier,
                channel,
                code,
                purpose,
                expires_at,
                attempt_count,
                created_at,
            },
        ))
    }

    pub async fn increment_attempts(&self, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE otp_codes SET attempt_count = attempt_count + 1 WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Remove OTP after successful use (one-time use).
    pub async fn delete(&self, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM otp_codes WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
