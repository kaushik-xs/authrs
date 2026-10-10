//! Mock OIDC identity provider for tests.
//!
//! Serves token and JWKS endpoints on a local `wiremock` server and signs ID tokens with the
//! fixture RSA keys in `tests/fixtures`. Shared by the OauthService component tests (pulled
//! into `src/services/oauth.rs` with `#[path]`) and the HTTP end-to-end tests, so it depends
//! only on dev-dependencies, never on `crate::` / `authrs::` items.
#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

pub const KID_A: &str = "test-key-a";
pub const KID_B: &str = "test-key-b";
pub const KEY_A_PEM: &str = include_str!("../fixtures/test_rsa_a.pem");
pub const KEY_B_PEM: &str = include_str!("../fixtures/test_rsa_b.pem");
pub const JWKS_A: &str = include_str!("../fixtures/jwks_a.json");
pub const JWKS_B: &str = include_str!("../fixtures/jwks_b.json");

pub const CLIENT_ID: &str = "test-client-id";
pub const CLIENT_SECRET: &str = "test-client-secret";
pub const REDIRECT_URL: &str = "https://app.example.test/oauth/callback";

pub const GOOGLE_AUTH_PATH: &str = "/google/auth";
pub const GOOGLE_TOKEN_PATH: &str = "/google/token";
pub const GOOGLE_JWKS_PATH: &str = "/google/jwks";
/// Microsoft endpoints live under `{uri}{MS_BASE_PATH}/{authority}/...`.
pub const MS_BASE_PATH: &str = "/ms";

pub const MS_ORG_TID: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
pub const MS_CONSUMERS_TID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// Both JWKS fixtures merged, as a provider publishes during key rotation.
pub fn jwks_ab() -> Value {
    let a: Value = serde_json::from_str(JWKS_A).unwrap();
    let b: Value = serde_json::from_str(JWKS_B).unwrap();
    let mut keys = a["keys"].as_array().unwrap().clone();
    keys.extend(b["keys"].as_array().unwrap().iter().cloned());
    json!({ "keys": keys })
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Sign `claims` as an RS256 JWT with the given PEM key and `kid` header.
pub fn sign_with(claims: &Value, pem: &str, kid: Option<&str>) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(String::from);
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("fixture RSA key");
    jsonwebtoken::encode(&header, claims, &key).expect("sign test token")
}

/// Sign with fixture key A (`kid = test-key-a`), the key served by [`JWKS_A`].
pub fn sign(claims: &Value) -> String {
    sign_with(claims, KEY_A_PEM, Some(KID_A))
}

/// Valid Google ID-token claims for [`CLIENT_ID`].
pub fn google_claims(sub: &str, nonce: &str, email: Option<&str>, email_verified: bool) -> Value {
    json!({
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "sub": sub,
        "iat": now(),
        "exp": now() + 600,
        "nonce": nonce,
        "email": email,
        "email_verified": email_verified,
        "given_name": "Ada",
        "family_name": "Lovelace",
    })
}

/// Valid Microsoft v2.0 ID-token claims for [`CLIENT_ID`], issued by directory `tid`.
pub fn microsoft_claims(tid: &str, oid: &str, nonce: &str, email: Option<&str>, xms_edov: bool) -> Value {
    json!({
        "iss": format!("https://login.microsoftonline.com/{}/v2.0", tid),
        "aud": CLIENT_ID,
        "sub": "pairwise-subject",
        "iat": now(),
        "exp": now() + 600,
        "nonce": nonce,
        "email": email,
        "name": "Grace Hopper",
        "oid": oid,
        "tid": tid,
        "xms_edov": xms_edov,
    })
}

/// The tenant's kv_store `oauth/<provider>` value pointing at the mock client.
pub fn oauth_config(tenant: Option<&str>, allow_signup: Option<bool>) -> Value {
    json!({
        "clientId": CLIENT_ID,
        "clientSecret": CLIENT_SECRET,
        "redirectUrl": REDIRECT_URL,
        "tenant": tenant,
        "allowSignup": allow_signup,
    })
}

/// Parse an `application/x-www-form-urlencoded` request body.
pub fn form_fields(req: &Request) -> Vec<(String, String)> {
    url::form_urlencoded::parse(&req.body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

pub fn form_field(req: &Request, name: &str) -> Option<String> {
    form_fields(req).into_iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

/// Matches a token request whose `code_verifier` hashes (S256) to `challenge` — i.e. the
/// service sent back the verifier that belongs to the challenge it put in the authorize URL.
pub struct PkceMatches(pub String);

impl wiremock::Match for PkceMatches {
    fn matches(&self, req: &Request) -> bool {
        form_field(req, "code_verifier")
            .map(|v| URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes())) == self.0)
            .unwrap_or(false)
    }
}

pub struct MockIdp {
    pub server: MockServer,
}

impl MockIdp {
    pub async fn start() -> Self {
        Self { server: MockServer::start().await }
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    pub fn google_auth_url(&self) -> String {
        format!("{}{}", self.uri(), GOOGLE_AUTH_PATH)
    }
    pub fn google_token_url(&self) -> String {
        format!("{}{}", self.uri(), GOOGLE_TOKEN_PATH)
    }
    pub fn google_jwks_url(&self) -> String {
        format!("{}{}", self.uri(), GOOGLE_JWKS_PATH)
    }
    pub fn microsoft_base(&self) -> String {
        format!("{}{}", self.uri(), MS_BASE_PATH)
    }

    /// Serve `jwks` at `at`. With `expect`, the server verifies the call count on drop.
    pub async fn serve_jwks(&self, at: &str, jwks: Value, expect: Option<u64>) {
        let mut mock = Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks));
        if let Some(n) = expect {
            mock = mock.expect(n);
        }
        mock.mount(&self.server).await;
    }

    /// Serve a successful token response carrying `id_token` at `at`.
    pub async fn serve_id_token(&self, at: &str, id_token: &str) {
        self.serve_token_response(at, 200, json!({ "access_token": "at", "token_type": "Bearer", "id_token": id_token }))
            .await;
    }

    pub async fn serve_token_response(&self, at: &str, status: u16, body: Value) {
        Mock::given(method("POST"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&self.server)
            .await;
    }

    /// Token requests received so far, as parsed form bodies.
    pub async fn token_requests(&self, at: &str) -> Vec<Vec<(String, String)>> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.method.as_str() == "POST" && r.url.path() == at)
            .map(form_fields)
            .collect()
    }

    pub async fn request_count(&self, at: &str) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == at)
            .count()
    }
}
