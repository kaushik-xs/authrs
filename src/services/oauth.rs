//! OAuth service: Google, Microsoft, state, callback.
//!
//! Authorization-code flow with PKCE (S256) and an OIDC nonce. The redirect step stores a
//! single-use state (tenant, provider, PKCE verifier, nonce); the callback step consumes it,
//! exchanges the code at the provider's token endpoint and verifies the returned ID token
//! against the provider's published JWKS. Account linking / membership provisioning happens
//! in `AuthService::login_oauth` using the normalized `OauthProfile` produced here.

use crate::error::AppError;
use crate::repo::oauth::OauthRepo;
use crate::services::tenant_config::{OauthConfig, TenantConfigLoader};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use jsonwebtoken::{jwk::{Jwk, JwkSet}, Algorithm, DecodingKey, Validation};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

const STATE_TTL_MINS: i64 = 10;
const OIDC_SCOPES: &str = "openid email profile";
/// Signing keys rotate rarely; refresh hourly, or sooner when an unknown `kid` shows up.
const JWKS_CACHE_TTL_SECS: u64 = 3600;
/// Minimum gap between forced JWKS refetches, so tokens with bogus `kid`s cannot make us
/// hammer the provider.
const JWKS_MIN_REFRESH_SECS: u64 = 60;
const HTTP_TIMEOUT_SECS: u64 = 10;

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

const MICROSOFT_LOGIN_BASE: &str = "https://login.microsoftonline.com";
const MICROSOFT_DEFAULT_AUTHORITY: &str = "common";
/// Entra tenant ID that personal Microsoft accounts (outlook.com, hotmail.com, ...) sign in through.
const MICROSOFT_CONSUMERS_TENANT_ID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Google,
    Microsoft,
}

impl Provider {
    pub fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "google" => Ok(Provider::Google),
            "microsoft" => Ok(Provider::Microsoft),
            _ => Err(AppError::NotFound(format!("Unsupported OAuth provider '{}'", s))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Google => "google",
            Provider::Microsoft => "microsoft",
        }
    }
}

/// Microsoft authority segment ("common" | "organizations" | "consumers" | tenant).
fn microsoft_authority(cfg: &OauthConfig) -> &str {
    cfg.tenant
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .unwrap_or(MICROSOFT_DEFAULT_AUTHORITY)
}

/// Where each provider's authorize / token / JWKS endpoints live. Production uses
/// [`ProviderEndpoints::default`]; tests point these at a mock identity provider.
#[derive(Clone, Debug)]
pub struct ProviderEndpoints {
    pub google_auth_url: String,
    pub google_token_url: String,
    pub google_jwks_url: String,
    /// Base for Microsoft's authority-scoped endpoints (`{base}/{authority}/...`). Only the
    /// endpoints move; ID-token issuers are always checked against the real login host.
    pub microsoft_login_base: String,
}

impl Default for ProviderEndpoints {
    fn default() -> Self {
        Self {
            google_auth_url: GOOGLE_AUTH_URL.to_string(),
            google_token_url: GOOGLE_TOKEN_URL.to_string(),
            google_jwks_url: GOOGLE_JWKS_URL.to_string(),
            microsoft_login_base: MICROSOFT_LOGIN_BASE.to_string(),
        }
    }
}

impl ProviderEndpoints {
    fn auth_url(&self, provider: Provider, cfg: &OauthConfig) -> String {
        match provider {
            Provider::Google => self.google_auth_url.clone(),
            Provider::Microsoft => format!(
                "{}/{}/oauth2/v2.0/authorize",
                self.microsoft_login_base,
                microsoft_authority(cfg)
            ),
        }
    }

    fn token_url(&self, provider: Provider, cfg: &OauthConfig) -> String {
        match provider {
            Provider::Google => self.google_token_url.clone(),
            Provider::Microsoft => format!(
                "{}/{}/oauth2/v2.0/token",
                self.microsoft_login_base,
                microsoft_authority(cfg)
            ),
        }
    }

    fn jwks_url(&self, provider: Provider, cfg: &OauthConfig) -> String {
        match provider {
            Provider::Google => self.google_jwks_url.clone(),
            Provider::Microsoft => format!(
                "{}/{}/discovery/v2.0/keys",
                self.microsoft_login_base,
                microsoft_authority(cfg)
            ),
        }
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Providers emit boolean claims either as JSON booleans or as "true"/"false" strings.
fn claim_is_true(v: &Option<serde_json::Value>) -> bool {
    match v {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

#[derive(serde::Deserialize)]
struct TokenErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
}

/// The subset of ID-token claims we use from either provider.
#[derive(serde::Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    nonce: Option<String>,
    email: Option<String>,
    /// Google: whether Google has verified the email.
    email_verified: Option<serde_json::Value>,
    given_name: Option<String>,
    family_name: Option<String>,
    name: Option<String>,
    /// Microsoft: immutable object ID of the user within its directory.
    oid: Option<String>,
    /// Microsoft: the Entra tenant (directory) the user signed in through.
    tid: Option<String>,
    /// Microsoft optional claim: email domain owner verified (must be enabled on the app
    /// registration). Without it, a Microsoft `email` claim is treated as unverified.
    xms_edov: Option<serde_json::Value>,
}

/// Provider account normalized for account linking.
#[derive(Debug, Clone)]
pub struct OauthProfile {
    /// Stable account key stored in `identity_oauth_accounts.provider_user_id`.
    pub provider_user_id: String,
    /// Lowercased email asserted by the provider, if any.
    pub email: Option<String>,
    /// True only when the provider vouches the email belongs to this account.
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Result of a completed callback: the tenant that started the flow, the verified
/// provider profile, and whether that tenant allows OAuth auto-provisioning.
pub struct OauthCallback {
    pub tenant_id: String,
    pub profile: OauthProfile,
    pub allow_signup: bool,
}

struct CachedJwks {
    keys: JwkSet,
    fetched_at: Instant,
}

#[derive(Clone)]
pub struct OauthService {
    http: reqwest::Client,
    repo: OauthRepo,
    tenant_config: TenantConfigLoader,
    endpoints: ProviderEndpoints,
    jwks_cache: Arc<RwLock<HashMap<String, CachedJwks>>>,
}

impl OauthService {
    pub fn new(repo: OauthRepo, tenant_config: TenantConfigLoader) -> Result<Self, AppError> {
        Self::with_endpoints(repo, tenant_config, ProviderEndpoints::default())
    }

    pub fn with_endpoints(
        repo: OauthRepo,
        tenant_config: TenantConfigLoader,
        endpoints: ProviderEndpoints,
    ) -> Result<Self, AppError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .map_err(|e| AppError::Internal(format!("HTTP client init: {e}")))?;
        Ok(Self {
            http,
            repo,
            tenant_config,
            endpoints,
            jwks_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    async fn load_config(&self, tenant_id: &str, provider: Provider) -> Result<OauthConfig, AppError> {
        self.tenant_config
            .get_oauth(tenant_id, provider.as_str())
            .await?
            .ok_or_else(|| {
                AppError::BadRequest(format!(
                    "OAuth provider '{}' is not configured for this tenant",
                    provider.as_str()
                ))
            })
    }

    /// Start a sign-in: persist a single-use state and build the provider authorize URL.
    /// Returns `(authorization_url, state)`.
    pub async fn authorization_url(
        &self,
        tenant_id: &str,
        provider: Provider,
    ) -> Result<(String, String), AppError> {
        let cfg = self.load_config(tenant_id, provider).await?;
        let state = random_token();
        let verifier = random_token();
        let nonce = random_token();
        let expires_at = Utc::now() + Duration::minutes(STATE_TTL_MINS);
        self.repo
            .create_state(&state, tenant_id, provider.as_str(), &verifier, &nonce, expires_at)
            .await?;

        let challenge = pkce_challenge(&verifier);
        let url = reqwest::Url::parse_with_params(
            &self.endpoints.auth_url(provider, &cfg),
            &[
                ("client_id", cfg.client_id.as_str()),
                ("response_type", "code"),
                ("redirect_uri", cfg.redirect_url.as_str()),
                ("scope", OIDC_SCOPES),
                ("state", state.as_str()),
                ("nonce", nonce.as_str()),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
                ("prompt", "select_account"),
            ],
        )
        .map_err(|e| AppError::Internal(format!("Invalid OAuth authorize URL: {e}")))?;
        Ok((url.to_string(), state))
    }

    /// Finish a sign-in: consume the state, exchange the code, verify the ID token and
    /// return the normalized provider profile together with the originating tenant.
    pub async fn complete(
        &self,
        provider: Provider,
        code: &str,
        state: &str,
    ) -> Result<OauthCallback, AppError> {
        let pending = self
            .repo
            .take_state(state)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid or expired OAuth state".to_string()))?;
        if pending.provider != provider.as_str() {
            return Err(AppError::Unauthorized("OAuth state does not match provider".to_string()));
        }
        let cfg = self.load_config(&pending.tenant_id, provider).await?;

        let id_token = self
            .exchange_code(provider, &cfg, code, &pending.pkce_verifier)
            .await?;
        let claims = self.verify_id_token(provider, &cfg, &id_token).await?;
        if claims.nonce.as_deref() != Some(pending.nonce.as_str()) {
            return Err(AppError::Unauthorized("ID token nonce mismatch".to_string()));
        }
        let profile = Self::profile_from_claims(provider, claims)?;
        Ok(OauthCallback {
            tenant_id: pending.tenant_id,
            profile,
            allow_signup: cfg.allow_signup.unwrap_or(true),
        })
    }

    async fn exchange_code(
        &self,
        provider: Provider,
        cfg: &OauthConfig,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<String, AppError> {
        let resp = self
            .http
            .post(self.endpoints.token_url(provider, cfg))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", cfg.redirect_url.as_str()),
                ("client_id", cfg.client_id.as_str()),
                ("client_secret", cfg.client_secret.as_str()),
                ("code_verifier", pkce_verifier),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("OAuth token request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err: TokenErrorResponse = resp.json().await.unwrap_or(TokenErrorResponse {
                error: None,
                error_description: None,
            });
            tracing::warn!(
                provider = provider.as_str(),
                %status,
                error = err.error.as_deref().unwrap_or(""),
                description = err.error_description.as_deref().unwrap_or(""),
                "OAuth code exchange rejected"
            );
            return Err(AppError::Unauthorized(format!(
                "OAuth code exchange failed: {}",
                err.error.as_deref().unwrap_or("unknown_error")
            )));
        }

        let body: TokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid OAuth token response: {e}")))?;
        body.id_token
            .ok_or_else(|| AppError::Unauthorized("Provider did not return an ID token".to_string()))
    }

    async fn verify_id_token(
        &self,
        provider: Provider,
        cfg: &OauthConfig,
        id_token: &str,
    ) -> Result<IdTokenClaims, AppError> {
        let invalid = |e: jsonwebtoken::errors::Error| {
            AppError::Unauthorized(format!("Invalid ID token: {e}"))
        };
        let header = jsonwebtoken::decode_header(id_token).map_err(invalid)?;
        // Both providers sign ID tokens with RS256; never let the token pick the algorithm.
        if header.alg != Algorithm::RS256 {
            return Err(AppError::Unauthorized("Unexpected ID token algorithm".to_string()));
        }
        let kid = header
            .kid
            .ok_or_else(|| AppError::Unauthorized("ID token has no key id".to_string()))?;
        let jwk = self.find_jwk(&self.endpoints.jwks_url(provider, cfg), &kid).await?;
        let key = DecodingKey::from_jwk(&jwk).map_err(invalid)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[cfg.client_id.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        if provider == Provider::Google {
            validation.set_issuer(&GOOGLE_ISSUERS);
        }
        let claims = jsonwebtoken::decode::<IdTokenClaims>(id_token, &key, &validation)
            .map_err(invalid)?
            .claims;

        if provider == Provider::Microsoft {
            Self::check_microsoft_issuer(cfg, &claims)?;
        }
        Ok(claims)
    }

    /// Microsoft's multi-tenant endpoints issue tokens whose issuer embeds the user's
    /// directory (`.../{tid}/v2.0`), so it is checked against `tid` here, then `tid` is
    /// checked against the configured authority.
    fn check_microsoft_issuer(cfg: &OauthConfig, claims: &IdTokenClaims) -> Result<(), AppError> {
        let tid = claims
            .tid
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized("ID token has no tenant id".to_string()))?;
        if claims.iss != format!("{}/{}/v2.0", MICROSOFT_LOGIN_BASE, tid) {
            return Err(AppError::Unauthorized("Invalid ID token issuer".to_string()));
        }
        let authority = microsoft_authority(cfg);
        let allowed = match authority.to_ascii_lowercase().as_str() {
            "common" => true,
            "organizations" => tid != MICROSOFT_CONSUMERS_TENANT_ID,
            "consumers" => tid == MICROSOFT_CONSUMERS_TENANT_ID,
            // A specific directory: Microsoft already scopes sign-in to it; also pin `tid`
            // when it is given as a GUID (a domain-name authority cannot be compared to `tid`).
            other => uuid::Uuid::parse_str(other).map_or(true, |_| tid.eq_ignore_ascii_case(other)),
        };
        if !allowed {
            return Err(AppError::Forbidden(
                "This Microsoft account is not permitted for this tenant".to_string(),
            ));
        }
        Ok(())
    }

    fn profile_from_claims(provider: Provider, claims: IdTokenClaims) -> Result<OauthProfile, AppError> {
        let email = non_empty(claims.email).map(|e| e.to_lowercase());
        let (provider_user_id, email_verified) = match provider {
            // Google `sub` is globally stable across client IDs.
            Provider::Google => (claims.sub, claim_is_true(&claims.email_verified)),
            Provider::Microsoft => {
                // `sub` is pairwise per app registration, and each authrs tenant registers its
                // own app, so it would differ per tenant for the same person. `tid` + `oid` is
                // stable across apps.
                let tid = claims.tid.clone().unwrap_or_default();
                let oid = non_empty(claims.oid)
                    .ok_or_else(|| AppError::Unauthorized("ID token has no object id".to_string()))?;
                // Entra lets directory admins set arbitrary unverified emails, so trust the
                // email only with the `xms_edov` claim. Personal accounts' emails are verified
                // by Microsoft at account creation.
                let verified =
                    claim_is_true(&claims.xms_edov) || tid == MICROSOFT_CONSUMERS_TENANT_ID;
                (format!("{}:{}", tid, oid), verified)
            }
        };

        let (mut first_name, mut last_name) = (non_empty(claims.given_name), non_empty(claims.family_name));
        if first_name.is_none() && last_name.is_none() {
            if let Some(full) = non_empty(claims.name) {
                match full.split_once(char::is_whitespace) {
                    Some((f, l)) => {
                        first_name = Some(f.to_string());
                        last_name = non_empty(Some(l.to_string()));
                    }
                    None => first_name = Some(full),
                }
            }
        }

        Ok(OauthProfile {
            provider_user_id,
            email_verified: email_verified && email.is_some(),
            email,
            first_name,
            last_name,
        })
    }

    /// Find a signing key by `kid`, using the cache and refetching the JWKS when the key
    /// is unknown (rotation) or the cache is stale.
    async fn find_jwk(&self, url: &str, kid: &str) -> Result<Jwk, AppError> {
        {
            let cache = self.jwks_cache.read().unwrap();
            if let Some(entry) = cache.get(url) {
                let age = entry.fetched_at.elapsed().as_secs();
                if age < JWKS_CACHE_TTL_SECS {
                    if let Some(jwk) = entry.keys.find(kid) {
                        return Ok(jwk.clone());
                    }
                }
                if age < JWKS_MIN_REFRESH_SECS {
                    return Err(AppError::Unauthorized("Unknown ID token signing key".to_string()));
                }
            }
        }

        let keys: JwkSet = self
            .http
            .get(url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| AppError::Internal(format!("Failed to fetch provider signing keys: {e}")))?
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Invalid provider signing keys: {e}")))?;
        let found = keys.find(kid).cloned();
        self.jwks_cache.write().unwrap().insert(
            url.to_string(),
            CachedJwks {
                keys,
                fetched_at: Instant::now(),
            },
        );
        found.ok_or_else(|| AppError::Unauthorized("Unknown ID token signing key".to_string()))
    }
}

#[cfg(test)]
#[path = "oauth_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "oauth_component_tests.rs"]
mod component_tests;
