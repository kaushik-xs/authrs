//! End-to-end tests: the full OAuth sign-in over HTTP through the real axum router, a real
//! Postgres and a mock identity provider. Covers redirect → provider → callback → session,
//! plus the security properties the flow depends on (PKCE, nonce, single-use state,
//! provider / tenant binding).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::mock_idp::*;
use common::*;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

struct App {
    state: Arc<authrs::api::state::AppState>,
    idp: MockIdp,
    pool: PgPool,
}

impl App {
    async fn new(pool: PgPool) -> Self {
        create_tenant(&pool, TENANT).await;
        create_tenant(&pool, OTHER_TENANT).await;
        let idp = MockIdp::start().await;
        let state = app_state_with_idp(&pool, &idp);
        Self { state, idp, pool }
    }

    async fn configure(&self, tenant: &str, provider: &str, cfg: Value) {
        set_kv(&self.pool, tenant, "oauth", provider, cfg).await;
    }

    async fn get(&self, uri: &str, tenant: Option<&str>, bearer: Option<&str>) -> (StatusCode, Value) {
        let mut req = Request::builder().method("GET").uri(uri);
        if let Some(t) = tenant {
            req = req.header("X-Tenant-ID", t);
        }
        if let Some(b) = bearer {
            req = req.header("Authorization", format!("Bearer {b}"));
        }
        let resp = authrs::routes::router()
            .with_state(self.state.clone())
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into()));
        (status, body)
    }

    /// GET /oauth/:provider and return the parsed authorize-URL query plus the URL itself.
    async fn start(&self, provider: &str, tenant: &str) -> (HashMap<String, String>, url::Url) {
        let (status, body) = self.get(&format!("/oauth/{provider}"), Some(tenant), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let u = url::Url::parse(body["authorizationUrl"].as_str().unwrap()).unwrap();
        let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
        assert_eq!(body["state"].as_str(), q.get("state").map(String::as_str));
        (q, u)
    }

    /// Mount a token endpoint that only answers when the PKCE verifier matches `challenge`.
    async fn token_endpoint(&self, at: &str, challenge: &str, id_token: &str) {
        Mock::given(method("POST"))
            .and(path(at))
            .and(PkceMatches(challenge.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id_token": id_token })))
            .mount(&self.idp.server)
            .await;
        // Anything else (wrong/missing verifier) is what a real provider does: invalid_grant.
        Mock::given(method("POST"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" })))
            .with_priority(10)
            .mount(&self.idp.server)
            .await;
    }

    async fn callback(&self, provider: &str, query: &str, tenant: Option<&str>) -> (StatusCode, Value) {
        self.get(&format!("/oauth/{provider}/callback?{query}"), tenant, None).await
    }
}

fn jwks_a() -> Value {
    serde_json::from_str(JWKS_A).unwrap()
}

async fn google_app(pool: PgPool) -> App {
    let app = App::new(pool).await;
    app.configure(TENANT, "google", oauth_config(None, None)).await;
    app.idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), None).await;
    app
}

/// Run the redirect step and arm the token endpoint with an ID token for `sub`.
async fn google_signin(app: &App, sub: &str, email: &str) -> String {
    let (q, _) = app.start("google", TENANT).await;
    let token = sign(&google_claims(sub, &q["nonce"], Some(email), true));
    app.token_endpoint(GOOGLE_TOKEN_PATH, &q["code_challenge"], &token).await;
    q["state"].clone()
}

// ---- Happy paths ----------------------------------------------------------------------

#[sqlx::test]
async fn google_sign_in_end_to_end(pool: PgPool) {
    let app = google_app(pool).await;
    let (q, u) = app.start("google", TENANT).await;

    // Authorize URL: right endpoint, OIDC + PKCE parameters.
    assert_eq!(format!("{}{}", &u[..url::Position::BeforePath], u.path()), app.idp.google_auth_url());
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(q["redirect_uri"], REDIRECT_URL);
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["scope"], "openid email profile");
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["prompt"], "select_account");
    assert!(!q.contains_key("client_secret"), "secret never goes to the browser");
    for k in ["state", "nonce", "code_challenge"] {
        assert_eq!(q[k].len(), 43, "{k} is 256-bit base64url");
    }
    assert_ne!(q["state"], q["nonce"]);

    let token = sign(&google_claims("google-sub-1", &q["nonce"], Some("ada@example.com"), true));
    app.token_endpoint(GOOGLE_TOKEN_PATH, &q["code_challenge"], &token).await;

    let (status, body) = app
        .callback("google", &format!("code=auth-code&state={}", q["state"]), Some(TENANT))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session_token = body["sessionToken"].as_str().expect("session token").to_string();
    assert!(body["expiresAt"].is_string());

    // The provider received the code and the verifier.
    let reqs = app.idp.token_requests(GOOGLE_TOKEN_PATH).await;
    let form: HashMap<_, _> = reqs.last().unwrap().iter().cloned().collect();
    assert_eq!(form["code"], "auth-code");
    assert_eq!(form["client_secret"], CLIENT_SECRET);

    // The session works against the rest of the API.
    let (status, me) = app.get("/session/me", None, Some(&session_token)).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["user"]["email"], "ada@example.com");
    let (status, v) = app.get("/session/validate", None, Some(&session_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["tenantId"], TENANT);
}

#[sqlx::test]
async fn callback_works_without_tenant_header(pool: PgPool) {
    // The tenant comes from the stored state, so the frontend needn't resend it.
    let app = google_app(pool).await;
    let state = google_signin(&app, "s", "a@example.com").await;
    let (status, body) = app.callback("google", &format!("code=c&state={state}"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[sqlx::test]
async fn microsoft_sign_in_end_to_end(pool: PgPool) {
    let app = App::new(pool).await;
    app.configure(TENANT, "microsoft", oauth_config(Some("organizations"), None)).await;
    app.idp
        .serve_jwks(&format!("{MS_BASE_PATH}/organizations/discovery/v2.0/keys"), jwks_a(), None)
        .await;

    let (q, u) = app.start("microsoft", TENANT).await;
    assert_eq!(u.path(), format!("{MS_BASE_PATH}/organizations/oauth2/v2.0/authorize"));
    let token = sign(&microsoft_claims(MS_ORG_TID, "oid-42", &q["nonce"], Some("grace@contoso.com"), true));
    app.token_endpoint(
        &format!("{MS_BASE_PATH}/organizations/oauth2/v2.0/token"),
        &q["code_challenge"],
        &token,
    )
    .await;

    let (status, body) = app.callback("microsoft", &format!("code=c&state={}", q["state"]), Some(TENANT)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let link: String = sqlx::query_scalar("SELECT provider_user_id FROM identity_oauth_accounts WHERE provider = 'microsoft'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(link, format!("{MS_ORG_TID}:oid-42"));
}

#[sqlx::test]
async fn microsoft_personal_account_blocked_for_organizations_tenant(pool: PgPool) {
    let app = App::new(pool).await;
    app.configure(TENANT, "microsoft", oauth_config(Some("organizations"), None)).await;
    app.idp
        .serve_jwks(&format!("{MS_BASE_PATH}/organizations/discovery/v2.0/keys"), jwks_a(), None)
        .await;
    let (q, _) = app.start("microsoft", TENANT).await;
    let token = sign(&microsoft_claims(MS_CONSUMERS_TID, "oid", &q["nonce"], Some("me@outlook.com"), false));
    app.token_endpoint(&format!("{MS_BASE_PATH}/organizations/oauth2/v2.0/token"), &q["code_challenge"], &token)
        .await;
    let (status, _) = app.callback("microsoft", &format!("code=c&state={}", q["state"]), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(link_count(&app.pool).await, 0);
}

// ---- State: single use, expiry, binding -----------------------------------------------

#[sqlx::test]
async fn state_cannot_be_replayed(pool: PgPool) {
    let app = google_app(pool).await;
    let state = google_signin(&app, "s", "a@example.com").await;
    let q = format!("code=c&state={state}");
    assert_eq!(app.callback("google", &q, None).await.0, StatusCode::OK);
    let (status, body) = app.callback("google", &q, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["message"].as_str().unwrap().contains("Invalid or expired OAuth state"));
}

#[sqlx::test]
async fn expired_state_is_rejected(pool: PgPool) {
    let app = google_app(pool).await;
    let state = google_signin(&app, "s", "a@example.com").await;
    sqlx::query("UPDATE oauth_states SET expires_at = now() - interval '1 second'")
        .execute(&app.pool)
        .await
        .unwrap();
    let (status, _) = app.callback("google", &format!("code=c&state={state}"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(app.idp.request_count(GOOGLE_TOKEN_PATH).await, 0, "no code exchange on a bad state");
}

#[sqlx::test]
async fn forged_state_is_rejected(pool: PgPool) {
    let app = google_app(pool).await;
    google_signin(&app, "s", "a@example.com").await;
    let (status, _) = app.callback("google", "code=c&state=forged-state-value", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(app.idp.request_count(GOOGLE_TOKEN_PATH).await, 0);
}

#[sqlx::test]
async fn state_is_bound_to_its_provider(pool: PgPool) {
    let app = google_app(pool).await;
    app.configure(TENANT, "microsoft", oauth_config(None, None)).await;
    let state = google_signin(&app, "s", "a@example.com").await;
    let (status, body) = app.callback("microsoft", &format!("code=c&state={state}"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["message"].as_str().unwrap().contains("does not match provider"));
    // The state was consumed by the failed attempt, so it can't be retried at google either.
    assert_eq!(app.callback("google", &format!("code=c&state={state}"), None).await.0, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn state_is_bound_to_its_tenant(pool: PgPool) {
    let app = google_app(pool).await;
    let state = google_signin(&app, "s", "a@example.com").await;
    let (status, body) = app.callback("google", &format!("code=c&state={state}"), Some(OTHER_TENANT)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["message"].as_str().unwrap().contains("different tenant"));
    assert_eq!(membership_count(&app.pool).await, 0, "no membership created in either tenant");
}

// ---- Provider responses ---------------------------------------------------------------

#[sqlx::test]
async fn nonce_mismatch_is_rejected(pool: PgPool) {
    let app = google_app(pool).await;
    let (q, _) = app.start("google", TENANT).await;
    // A token minted for a different authorization request (e.g. injected / replayed).
    let token = sign(&google_claims("s", "some-other-nonce", Some("a@example.com"), true));
    app.token_endpoint(GOOGLE_TOKEN_PATH, &q["code_challenge"], &token).await;
    let (status, body) = app.callback("google", &format!("code=c&state={}", q["state"]), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["message"].as_str().unwrap().contains("nonce"));
    assert_eq!(identity_count(&app.pool).await, 0);
}

#[sqlx::test]
async fn token_without_nonce_is_rejected(pool: PgPool) {
    let app = google_app(pool).await;
    let (q, _) = app.start("google", TENANT).await;
    let mut claims = google_claims("s", "x", Some("a@example.com"), true);
    claims.as_object_mut().unwrap().remove("nonce");
    app.token_endpoint(GOOGLE_TOKEN_PATH, &q["code_challenge"], &sign(&claims)).await;
    let (status, _) = app.callback("google", &format!("code=c&state={}", q["state"]), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn pkce_verifier_belongs_to_the_state(pool: PgPool) {
    // Two concurrent sign-ins: each callback must send its own verifier.
    let app = google_app(pool).await;
    let (q1, _) = app.start("google", TENANT).await;
    let (q2, _) = app.start("google", TENANT).await;
    assert_ne!(q1["code_challenge"], q2["code_challenge"]);
    let t2 = sign(&google_claims("s2", &q2["nonce"], Some("b@example.com"), true));
    // Only the second request's verifier is accepted by the provider.
    app.token_endpoint(GOOGLE_TOKEN_PATH, &q2["code_challenge"], &t2).await;

    let (status, body) = app.callback("google", &format!("code=c&state={}", q1["state"]), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body["message"].as_str().unwrap().contains("invalid_grant"));
    assert_eq!(app.callback("google", &format!("code=c&state={}", q2["state"]), None).await.0, StatusCode::OK);
}

#[sqlx::test]
async fn token_signed_by_unknown_key_is_rejected(pool: PgPool) {
    let app = google_app(pool).await;
    let (q, _) = app.start("google", TENANT).await;
    let token = sign_with(&google_claims("s", &q["nonce"], Some("a@example.com"), true), KEY_B_PEM, Some(KID_B));
    app.token_endpoint(GOOGLE_TOKEN_PATH, &q["code_challenge"], &token).await;
    let (status, _) = app.callback("google", &format!("code=c&state={}", q["state"]), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn provider_error_redirect_is_reported(pool: PgPool) {
    let app = google_app(pool).await;
    let (status, body) = app
        .callback("google", "error=access_denied&error_description=The+user+cancelled", None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["message"].as_str().unwrap().contains("The user cancelled"));
}

#[sqlx::test]
async fn provider_outage_is_a_server_error(pool: PgPool) {
    let app = google_app(pool).await;
    let (q, _) = app.start("google", TENANT).await;
    Mock::given(method("POST"))
        .and(path(GOOGLE_TOKEN_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>"))
        .mount(&app.idp.server)
        .await;
    let (status, _) = app.callback("google", &format!("code=c&state={}", q["state"]), None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

// ---- Request validation / configuration -----------------------------------------------

#[sqlx::test]
async fn callback_requires_code_and_state(pool: PgPool) {
    let app = google_app(pool).await;
    for q in ["", "code=c", "state=s", "code=&state=s", "code=c&state="] {
        let (status, _) = app.callback("google", q, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "query {q:?}");
    }
}

#[sqlx::test]
async fn unsupported_provider_is_not_found(pool: PgPool) {
    let app = google_app(pool).await;
    assert_eq!(app.get("/oauth/github", Some(TENANT), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(app.callback("github", "code=c&state=s", None).await.0, StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn unconfigured_provider_is_bad_request(pool: PgPool) {
    let app = google_app(pool).await;
    let (status, body) = app.get("/oauth/microsoft", Some(TENANT), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["message"].as_str().unwrap().contains("not configured"));
    // Config is per tenant.
    assert_eq!(app.get("/oauth/google", Some(OTHER_TENANT), None).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(count(&app.pool, "SELECT count(*) FROM oauth_states").await, 0);
}

#[sqlx::test]
async fn invalid_provider_config_is_treated_as_unconfigured(pool: PgPool) {
    let app = App::new(pool).await;
    app.configure(TENANT, "google", json!({ "clientId": "only-an-id" })).await;
    assert_eq!(app.get("/oauth/google", Some(TENANT), None).await.0, StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn redirect_requires_a_valid_tenant_header(pool: PgPool) {
    let app = google_app(pool).await;
    assert_eq!(app.get("/oauth/google", None, None).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(app.get("/oauth/google", Some("Not-Snake"), None).await.0, StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn allow_signup_false_blocks_new_users_end_to_end(pool: PgPool) {
    let app = App::new(pool).await;
    app.configure(TENANT, "google", oauth_config(None, Some(false))).await;
    app.idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), None).await;
    let state = google_signin(&app, "s", "new@example.com").await;
    let (status, _) = app.callback("google", &format!("code=c&state={state}"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(identity_count(&app.pool).await, 0);
}

#[sqlx::test]
async fn each_redirect_issues_a_distinct_state(pool: PgPool) {
    let app = google_app(pool).await;
    let mut states = std::collections::HashSet::new();
    for _ in 0..5 {
        let (q, _) = app.start("google", TENANT).await;
        assert!(states.insert(q["state"].clone()));
    }
    assert_eq!(count(&app.pool, "SELECT count(*) FROM oauth_states").await, 5);
}
