//! MFA secrets and backup codes repository.
//!
//! TOTP state lives on the global identity (`identities.mfa_secret` encrypted,
//! `mfa_enabled`, `mfa_last_used_step`); backup codes in `identity_backup_codes`; pending
//! login challenges in `mfa_challenges`.

use crate::error::AppError;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, FromRow)]
pub struct MfaChallenge {
    pub tenant_id: String,
    pub user_id: Uuid,
    pub attempt_count: i32,
}

#[derive(Clone)]
pub struct MfaRepo {
    pool: PgPool,
}

impl MfaRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Store a not-yet-confirmed secret (enrollment started). MFA stays disabled.
    pub async fn set_pending_secret(&self, identity_id: Uuid, encrypted_secret: &str) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE identities SET mfa_secret = $1, mfa_enabled = false, mfa_last_used_step = NULL, updated_at = now() WHERE id = $2",
        )
        .bind(encrypted_secret)
        .bind(identity_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Turn MFA on and replace the backup codes, atomically.
    pub async fn enable(&self, identity_id: Uuid, backup_code_hashes: &[String]) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE identities SET mfa_enabled = true, updated_at = now() WHERE id = $1")
            .bind(identity_id)
            .execute(&mut *tx)
            .await?;
        Self::replace_backup_codes_tx(&mut tx, identity_id, backup_code_hashes).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Turn MFA off: clear the secret, replay marker and backup codes.
    pub async fn disable(&self, identity_id: Uuid) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE identities SET mfa_enabled = false, mfa_secret = NULL, mfa_last_used_step = NULL, updated_at = now() WHERE id = $1",
        )
        .bind(identity_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM identity_backup_codes WHERE identity_id = $1")
            .bind(identity_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Record a TOTP step as used. Returns false if this step (or a later one) was already
    /// accepted — i.e. the code is a replay.
    pub async fn mark_step_used(&self, identity_id: Uuid, step: i64) -> Result<bool, AppError> {
        let res = sqlx::query(
            "UPDATE identities SET mfa_last_used_step = $2 \
             WHERE id = $1 AND (mfa_last_used_step IS NULL OR mfa_last_used_step < $2)",
        )
        .bind(identity_id)
        .bind(step)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    pub async fn replace_backup_codes(&self, identity_id: Uuid, hashes: &[String]) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?;
        Self::replace_backup_codes_tx(&mut tx, identity_id, hashes).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn replace_backup_codes_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        identity_id: Uuid,
        hashes: &[String],
    ) -> Result<(), AppError> {
        sqlx::query("DELETE FROM identity_backup_codes WHERE identity_id = $1")
            .bind(identity_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query(
            "INSERT INTO identity_backup_codes (identity_id, code_hash) SELECT $1, UNNEST($2::varchar[])",
        )
        .bind(identity_id)
        .bind(hashes)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Consume an unused backup code. Returns true if one matched.
    pub async fn consume_backup_code(&self, identity_id: Uuid, code_hash: &str) -> Result<bool, AppError> {
        let res = sqlx::query(
            "UPDATE identity_backup_codes SET consumed_at = now() \
             WHERE id = (SELECT id FROM identity_backup_codes \
                         WHERE identity_id = $1 AND code_hash = $2 AND consumed_at IS NULL LIMIT 1)",
        )
        .bind(identity_id)
        .bind(code_hash)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    pub async fn count_unused_backup_codes(&self, identity_id: Uuid) -> Result<i64, AppError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM identity_backup_codes WHERE identity_id = $1 AND consumed_at IS NULL",
        )
        .bind(identity_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    pub async fn create_challenge(
        &self,
        token: &str,
        tenant_id: &str,
        user_id: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        sqlx::query("DELETE FROM mfa_challenges WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO mfa_challenges (token, tenant_id, user_id, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(token)
        .bind(tenant_id)
        .bind(user_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_challenge(&self, token: &str) -> Result<Option<MfaChallenge>, AppError> {
        let row = sqlx::query_as::<_, MfaChallenge>(
            "SELECT tenant_id, user_id, attempt_count FROM mfa_challenges WHERE token = $1 AND expires_at > now()",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn increment_challenge_attempts(&self, token: &str) -> Result<(), AppError> {
        sqlx::query("UPDATE mfa_challenges SET attempt_count = attempt_count + 1 WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete a challenge; returns false if it was already redeemed (concurrent use).
    pub async fn delete_challenge(&self, token: &str) -> Result<bool, AppError> {
        let res = sqlx::query("DELETE FROM mfa_challenges WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() == 1)
    }
}
