//! Application configuration from environment.

use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub redis_url: Option<String>,
    pub redis_enabled: bool,
    pub log_level: String,
    pub server_host: String,
    pub server_port: u16,
    /// KV store encryption for sensitive values
    pub kv_store_encryption_key: Option<String>,
    /// SMTP for sending OTP emails (all optional; if set, email OTP request is enabled)
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_secure: bool,
    pub smtp_user: Option<String>,
    pub smtp_pass: Option<String>,
    pub smtp_from: Option<String>,
}

/// SMTP settings derived from Config for use in AppState (avoids holding full Config).
#[derive(Clone, Debug)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub secure: bool,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub from: String,
}

impl Config {
    pub fn smtp_config(&self) -> Option<SmtpConfig> {
        let host = self.smtp_host.as_ref()?.clone();
        let from = self.smtp_from.as_ref()?.clone();
        if host.is_empty() || from.is_empty() {
            return None;
        }
        Some(SmtpConfig {
            host,
            port: self.smtp_port.unwrap_or(587),
            secure: self.smtp_secure,
            user: self.smtp_user.clone(),
            pass: self.smtp_pass.clone(),
            from,
        })
    }
}

impl Config {
    pub fn from_env() -> Result<Self, env::VarError> {
        let database_url = env::var("DATABASE_URL")?;
        let redis_url = env::var("REDIS_URL").ok();
        let redis_enabled = env::var("REDIS_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);
        let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
        let server_host = env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let server_port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()
            .unwrap_or(3000);
        let kv_store_encryption_key = env::var("KV_STORE_ENCRYPTION_KEY").ok();

        let smtp_host = env::var("SMTP_HOST").ok().filter(|s| !s.is_empty());
        let smtp_port = env::var("SMTP_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(smtp_host.as_ref().and_then(|_| Some(587)));
        let smtp_secure = env::var("SMTP_SECURE")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);
        let smtp_user = env::var("SMTP_USER").ok().filter(|s| !s.is_empty());
        let smtp_pass = env::var("SMTP_PASS").ok().filter(|s| !s.is_empty());
        let smtp_from = env::var("SMTP_FROM").ok().filter(|s| !s.is_empty());

        Ok(Self {
            database_url,
            redis_url,
            redis_enabled,
            log_level,
            server_host,
            server_port,
            kv_store_encryption_key,
            smtp_host,
            smtp_port,
            smtp_secure,
            smtp_user,
            smtp_pass,
            smtp_from,
        })
    }

    /// True if SMTP is configured enough to send OTP emails (host + from required).
    pub fn smtp_configured(&self) -> bool {
        self.smtp_host
            .as_ref()
            .is_some_and(|h| !h.is_empty())
            && self.smtp_from.as_ref().is_some_and(|f| !f.is_empty())
    }

    pub fn redis_configured(&self) -> bool {
        self.redis_enabled && self.redis_url.as_ref().is_some_and(|u| !u.is_empty())
    }
}
