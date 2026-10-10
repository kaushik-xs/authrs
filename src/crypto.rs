//! Symmetric encryption at rest (AES-256-GCM) keyed by `KV_STORE_ENCRYPTION_KEY`.
//! Used for sensitive kv_store values and TOTP MFA secrets.

use crate::error::AppError;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;

#[derive(Clone)]
pub struct SecretCipher {
    key: Option<[u8; 32]>,
}

impl SecretCipher {
    /// Build from a base64 32-byte key. A missing/invalid key is allowed here; encrypt and
    /// decrypt then fail with a configuration error.
    pub fn new(key_base64: Option<&str>) -> Self {
        let key = key_base64
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|s| BASE64.decode(s.as_bytes()).ok())
            .and_then(|k| <[u8; 32]>::try_from(k.as_slice()).ok());
        Self { key }
    }

    fn cipher(&self) -> Result<Aes256Gcm, AppError> {
        let key = self.key.as_ref().ok_or_else(|| {
            AppError::Internal("KV_STORE_ENCRYPTION_KEY not set or invalid (need 32-byte base64)".to_string())
        })?;
        Ok(Aes256Gcm::new_from_slice(key).unwrap())
    }

    /// Encrypt to base64(nonce || ciphertext).
    pub fn encrypt(&self, plain: &str) -> Result<String, AppError> {
        let cipher = self.cipher()?;
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let nonce_arr = aes_gcm::Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce_arr, plain.as_bytes())
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let mut out = nonce.to_vec();
        out.extend(ciphertext);
        Ok(BASE64.encode(&out))
    }

    pub fn decrypt(&self, encrypted_b64: &str) -> Result<String, AppError> {
        let cipher = self.cipher()?;
        let bytes = BASE64
            .decode(encrypted_b64)
            .map_err(|_| AppError::Internal("Invalid base64 in encrypted value".to_string()))?;
        if bytes.len() < 12 {
            return Err(AppError::Internal("Encrypted value too short".to_string()));
        }
        let (nonce, ct) = bytes.split_at(12);
        let nonce_arr = aes_gcm::Nonce::from_slice(nonce);
        let plain = cipher
            .decrypt(nonce_arr, ct)
            .map_err(|_| AppError::Internal("Decryption failed (wrong key or corrupted data)".to_string()))?;
        String::from_utf8(plain).map_err(|e| AppError::Internal(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_missing_key() {
        let key = BASE64.encode([7u8; 32]);
        let c = SecretCipher::new(Some(&key));
        let enc = c.encrypt("JBSWY3DPEHPK3PXP").unwrap();
        assert_ne!(enc, "JBSWY3DPEHPK3PXP");
        assert_eq!(c.decrypt(&enc).unwrap(), "JBSWY3DPEHPK3PXP");
        assert!(SecretCipher::new(None).encrypt("x").is_err());
    }
}
