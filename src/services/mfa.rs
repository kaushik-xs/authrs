//! MFA service: TOTP, backup codes, enable/verify.
//!
//! Authenticator-app TOTP (RFC 6238: SHA-1, 6 digits, 30 s step, ±1 step skew — the
//! parameters Google/Microsoft Authenticator, Authy, 1Password etc. expect) plus single-use
//! backup codes. MFA is a property of the global identity, so it applies in every tenant.

use crate::crypto::SecretCipher;
use crate::domain::identity::Identity;
use crate::error::AppError;
use crate::repo::mfa::MfaRepo;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};

const TOTP_DIGITS: usize = 6;
const TOTP_STEP_SECS: u64 = 30;
const TOTP_SKEW_STEPS: u64 = 1;
const SECRET_BYTES: usize = 20; // 160-bit, as recommended by RFC 4226
const BACKUP_CODE_COUNT: usize = 10;
const BACKUP_CODE_LEN: usize = 10;
/// Crockford-style base32 alphabet without the easily confused i, l, o, u.
const BACKUP_CODE_ALPHABET: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Normalize user input: drop spaces/dashes, lowercase.
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_lowercase()
}

fn is_totp_code(code: &str) -> bool {
    code.len() == TOTP_DIGITS && code.chars().all(|c| c.is_ascii_digit())
}

fn hash_backup_code(normalized: &str) -> String {
    Sha256::digest(normalized.as_bytes())
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn totp_for(secret: Vec<u8>) -> TOTP {
    TOTP::new_unchecked(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW_STEPS as u8,
        TOTP_STEP_SECS,
        secret,
        None,
        String::new(),
    )
}

/// The time step a code is valid for (within ±skew of `now`), if any.
fn matching_step(secret: &[u8], code: &str, now: u64) -> Option<u64> {
    let totp = totp_for(secret.to_vec());
    let current = now / TOTP_STEP_SECS;
    (current.saturating_sub(TOTP_SKEW_STEPS)..=current + TOTP_SKEW_STEPS)
        .find(|step| constant_time_eq(totp.generate(step * TOTP_STEP_SECS).as_bytes(), code.as_bytes()))
}

fn generate_backup_codes() -> Vec<String> {
    let mut rng = rand::rngs::OsRng;
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            let raw: String = (0..BACKUP_CODE_LEN)
                .map(|_| BACKUP_CODE_ALPHABET[rng.gen_range(0..BACKUP_CODE_ALPHABET.len())] as char)
                .collect();
            format!("{}-{}", &raw[..BACKUP_CODE_LEN / 2], &raw[BACKUP_CODE_LEN / 2..])
        })
        .collect()
}

/// A started enrollment: what the user adds to their authenticator app.
pub struct MfaEnrollment {
    /// Base32 secret for manual entry.
    pub secret: String,
    /// `otpauth://totp/...` URI to render as a QR code.
    pub otpauth_url: String,
}

#[derive(Clone)]
pub struct MfaService {
    repo: MfaRepo,
    cipher: SecretCipher,
    issuer: String,
}

impl MfaService {
    pub fn new(repo: MfaRepo, cipher: SecretCipher, issuer: String) -> Self {
        // `:` separates issuer and account in otpauth labels.
        let issuer = issuer.replace(':', "");
        Self { repo, cipher, issuer }
    }

    fn now() -> u64 {
        chrono::Utc::now().timestamp().max(0) as u64
    }

    fn decrypt_secret(&self, identity: &Identity) -> Result<Option<Vec<u8>>, AppError> {
        let Some(enc) = identity.mfa_secret.as_deref() else { return Ok(None) };
        let encoded = self.cipher.decrypt(enc)?;
        let bytes = Secret::Encoded(encoded)
            .to_bytes()
            .map_err(|e| AppError::Internal(format!("Stored MFA secret is invalid: {e:?}")))?;
        Ok(Some(bytes))
    }

    /// Start (or restart) enrollment: generate and store a pending secret.
    pub async fn begin_enrollment(&self, identity: &Identity, account_label: &str) -> Result<MfaEnrollment, AppError> {
        if identity.mfa_enabled {
            return Err(AppError::Conflict("MFA is already enabled".to_string()));
        }
        let mut bytes = vec![0u8; SECRET_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let encoded = Secret::Raw(bytes.clone()).to_encoded().to_string();
        self.repo
            .set_pending_secret(identity.id, &self.cipher.encrypt(&encoded)?)
            .await?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW_STEPS as u8,
            TOTP_STEP_SECS,
            bytes,
            Some(self.issuer.clone()),
            account_label.replace(':', ""),
        )
        .map_err(|e| AppError::Internal(format!("TOTP init: {e:?}")))?;
        Ok(MfaEnrollment {
            secret: encoded,
            otpauth_url: totp.get_url(),
        })
    }

    /// Confirm enrollment with a code from the app; enables MFA and returns fresh backup
    /// codes (shown to the user once).
    pub async fn confirm_enrollment(&self, identity: &Identity, code: &str) -> Result<Vec<String>, AppError> {
        if identity.mfa_enabled {
            return Err(AppError::Conflict("MFA is already enabled".to_string()));
        }
        let secret = self
            .decrypt_secret(identity)?
            .ok_or_else(|| AppError::BadRequest("Start MFA enrollment first".to_string()))?;
        let code = normalize_code(code);
        let step = is_totp_code(&code)
            .then(|| matching_step(&secret, &code, Self::now()))
            .flatten()
            .ok_or_else(|| AppError::Unauthorized("Invalid MFA code".to_string()))?;
        self.repo.mark_step_used(identity.id, step as i64).await?;
        let codes = generate_backup_codes();
        let hashes: Vec<String> = codes.iter().map(|c| hash_backup_code(&normalize_code(c))).collect();
        self.repo.enable(identity.id, &hashes).await?;
        Ok(codes)
    }

    /// Check a second-factor code for an identity with MFA enabled: a current TOTP code
    /// (not previously used) or an unused backup code (consumed on success).
    pub async fn verify(&self, identity: &Identity, code: &str) -> Result<bool, AppError> {
        if !identity.mfa_enabled {
            return Ok(false);
        }
        let code = normalize_code(code);
        if is_totp_code(&code) {
            let Some(secret) = self.decrypt_secret(identity)? else { return Ok(false) };
            return match matching_step(&secret, &code, Self::now()) {
                Some(step) => self.repo.mark_step_used(identity.id, step as i64).await,
                None => Ok(false),
            };
        }
        if code.len() != BACKUP_CODE_LEN {
            return Ok(false);
        }
        self.repo
            .consume_backup_code(identity.id, &hash_backup_code(&code))
            .await
    }

    async fn require_valid_code(&self, identity: &Identity, code: &str) -> Result<(), AppError> {
        if !identity.mfa_enabled {
            return Err(AppError::BadRequest("MFA is not enabled".to_string()));
        }
        if !self.verify(identity, code).await? {
            return Err(AppError::Unauthorized("Invalid MFA code".to_string()));
        }
        Ok(())
    }

    /// Turn MFA off (requires a valid code).
    pub async fn disable(&self, identity: &Identity, code: &str) -> Result<(), AppError> {
        self.require_valid_code(identity, code).await?;
        self.repo.disable(identity.id).await
    }

    /// Replace all backup codes (requires a valid code).
    pub async fn regenerate_backup_codes(&self, identity: &Identity, code: &str) -> Result<Vec<String>, AppError> {
        self.require_valid_code(identity, code).await?;
        let codes = generate_backup_codes();
        let hashes: Vec<String> = codes.iter().map(|c| hash_backup_code(&normalize_code(c))).collect();
        self.repo.replace_backup_codes(identity.id, &hashes).await?;
        Ok(codes)
    }

    pub async fn backup_codes_remaining(&self, identity: &Identity) -> Result<i64, AppError> {
        if !identity.mfa_enabled {
            return Ok(0);
        }
        self.repo.count_unused_backup_codes(identity.id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test secret (ASCII "12345678901234567890"), truncated to 6 digits.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn totp_matches_rfc6238_vectors() {
        assert_eq!(matching_step(RFC_SECRET, "287082", 59), Some(1));
        assert_eq!(matching_step(RFC_SECRET, "081804", 1111111109), Some(1111111109 / 30));
        assert_eq!(matching_step(RFC_SECRET, "005924", 1234567890), Some(1234567890 / 30));
    }

    #[test]
    fn totp_allows_one_step_skew_only() {
        // "081804" is valid for step 37037036 (t = 1111111109).
        assert!(matching_step(RFC_SECRET, "081804", 1111111109 + 30).is_some());
        assert!(matching_step(RFC_SECRET, "081804", 1111111109 + 90).is_none());
        assert!(matching_step(RFC_SECRET, "000000", 1111111109).is_none());
    }

    #[test]
    fn backup_codes_are_well_formed_and_normalize() {
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        for c in &codes {
            assert_eq!(c.len(), BACKUP_CODE_LEN + 1);
            let n = normalize_code(&c.to_uppercase().replace('-', " - "));
            assert_eq!(n.len(), BACKUP_CODE_LEN);
            assert_eq!(hash_backup_code(&n), hash_backup_code(&normalize_code(c)));
        }
    }

    #[test]
    fn code_kind_detection() {
        assert!(is_totp_code(&normalize_code("123 456")));
        assert!(!is_totp_code("12345"));
        assert!(!is_totp_code("abcdef"));
    }
}
