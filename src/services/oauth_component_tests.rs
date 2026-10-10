//! Component tests for OauthService's network-facing steps — code exchange, ID-token
//! verification and the JWKS cache — against a mock identity provider (wiremock + fixture
//! RSA keys). No database: these paths never touch the repo, so it gets a lazy pool.

use super::*;
use crate::repo::kv_store::KvStoreRepo;
use serde_json::json;
use std::time::Duration as StdDuration;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, ResponseTemplate};

#[path = "../../tests/common/mock_idp.rs"]
mod mock_idp;
use mock_idp::*;

fn service(idp: &MockIdp) -> OauthService {
    // Never connected: none of the code under test reaches the database.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused@127.0.0.1:1/unused")
        .unwrap();
    let kv = KvStoreRepo::new(pool.clone(), None).unwrap();
    OauthService::with_endpoints(
        OauthRepo::new(pool),
        TenantConfigLoader::new(kv),
        ProviderEndpoints {
            google_auth_url: idp.google_auth_url(),
            google_token_url: idp.google_token_url(),
            google_jwks_url: idp.google_jwks_url(),
            microsoft_login_base: idp.microsoft_base(),
        },
    )
    .unwrap()
}

fn cfg(tenant: Option<&str>) -> OauthConfig {
    serde_json::from_value(oauth_config(tenant, None)).unwrap()
}

fn ms_jwks_path(authority: &str) -> String {
    format!("{}/{}/discovery/v2.0/keys", MS_BASE_PATH, authority)
}

fn ms_token_path(authority: &str) -> String {
    format!("{}/{}/oauth2/v2.0/token", MS_BASE_PATH, authority)
}

fn jwks_a() -> serde_json::Value {
    serde_json::from_str(JWKS_A).unwrap()
}

fn jwks_b() -> serde_json::Value {
    serde_json::from_str(JWKS_B).unwrap()
}

fn unauthorized_containing<T>(r: Result<T, AppError>, needle: &str) -> bool {
    matches!(r, Err(AppError::Unauthorized(ref m)) if m.contains(needle))
}

/// Pretend the cached JWKS for `url` was fetched `secs` ago.
fn age_cache(svc: &OauthService, url: &str, secs: u64) {
    let mut cache = svc.jwks_cache.write().unwrap();
    let entry = cache.get_mut(url).expect("cached JWKS");
    entry.fetched_at = Instant::now()
        .checked_sub(StdDuration::from_secs(secs))
        .expect("monotonic clock far enough from boot");
}

// ---- Code exchange --------------------------------------------------------------------

#[tokio::test]
async fn exchange_code_posts_pkce_form_and_returns_id_token() {
    let idp = MockIdp::start().await;
    idp.serve_id_token(GOOGLE_TOKEN_PATH, "the.id.token").await;
    let svc = service(&idp);

    let token = svc
        .exchange_code(Provider::Google, &cfg(None), "auth-code", "the-verifier")
        .await
        .unwrap();
    assert_eq!(token, "the.id.token");

    let reqs = idp.token_requests(GOOGLE_TOKEN_PATH).await;
    assert_eq!(reqs.len(), 1);
    let form: HashMap<_, _> = reqs[0].iter().cloned().collect();
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["code"], "auth-code");
    assert_eq!(form["code_verifier"], "the-verifier");
    assert_eq!(form["client_id"], CLIENT_ID);
    assert_eq!(form["client_secret"], CLIENT_SECRET);
    assert_eq!(form["redirect_uri"], REDIRECT_URL);
}

#[tokio::test]
async fn exchange_code_uses_microsoft_authority_token_endpoint() {
    let idp = MockIdp::start().await;
    idp.serve_id_token(&ms_token_path("organizations"), "ms.id.token").await;
    let token = service(&idp)
        .exchange_code(Provider::Microsoft, &cfg(Some("organizations")), "c", "v")
        .await
        .unwrap();
    assert_eq!(token, "ms.id.token");
}

#[tokio::test]
async fn exchange_code_maps_provider_error_to_unauthorized() {
    let idp = MockIdp::start().await;
    idp.serve_token_response(
        GOOGLE_TOKEN_PATH,
        400,
        json!({ "error": "invalid_grant", "error_description": "Bad Request" }),
    )
    .await;
    let r = service(&idp).exchange_code(Provider::Google, &cfg(None), "c", "v").await;
    assert!(unauthorized_containing(r, "invalid_grant"));
}

#[tokio::test]
async fn exchange_code_tolerates_non_json_error_body() {
    let idp = MockIdp::start().await;
    Mock::given(method("POST"))
        .and(path(GOOGLE_TOKEN_PATH))
        .respond_with(ResponseTemplate::new(502).set_body_string("<html>bad gateway</html>"))
        .mount(&idp.server)
        .await;
    let r = service(&idp).exchange_code(Provider::Google, &cfg(None), "c", "v").await;
    assert!(unauthorized_containing(r, "unknown_error"));
}

#[tokio::test]
async fn exchange_code_requires_an_id_token() {
    let idp = MockIdp::start().await;
    idp.serve_token_response(GOOGLE_TOKEN_PATH, 200, json!({ "access_token": "at" })).await;
    let r = service(&idp).exchange_code(Provider::Google, &cfg(None), "c", "v").await;
    assert!(unauthorized_containing(r, "did not return an ID token"));
}

#[tokio::test]
async fn exchange_code_rejects_malformed_success_body() {
    let idp = MockIdp::start().await;
    Mock::given(method("POST"))
        .and(path(GOOGLE_TOKEN_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&idp.server)
        .await;
    let r = service(&idp).exchange_code(Provider::Google, &cfg(None), "c", "v").await;
    assert!(matches!(r, Err(AppError::Internal(_))));
}

#[tokio::test]
async fn exchange_code_reports_unreachable_provider_as_internal() {
    let idp = MockIdp::start().await;
    let mut svc = service(&idp);
    svc.endpoints.google_token_url = "http://127.0.0.1:1/token".into();
    let r = svc.exchange_code(Provider::Google, &cfg(None), "c", "v").await;
    assert!(matches!(r, Err(AppError::Internal(ref m)) if m.contains("token request failed")));
}

#[tokio::test]
async fn exchange_code_does_not_leak_client_secret_in_errors() {
    let idp = MockIdp::start().await;
    Mock::given(method("POST"))
        .and(path(GOOGLE_TOKEN_PATH))
        .and(body_string_contains("client_secret"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({ "error": "invalid_client" })))
        .mount(&idp.server)
        .await;
    let err = service(&idp)
        .exchange_code(Provider::Google, &cfg(None), "c", "v")
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("invalid_client"));
    assert!(!err.contains(CLIENT_SECRET));
}

// ---- ID-token verification: Google ----------------------------------------------------

#[tokio::test]
async fn verifies_valid_google_token() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), None).await;
    let token = sign(&google_claims("sub-1", "n-1", Some("ada@gmail.com"), true));
    let c = service(&idp).verify_id_token(Provider::Google, &cfg(None), &token).await.unwrap();
    assert_eq!(c.sub, "sub-1");
    assert_eq!(c.nonce.as_deref(), Some("n-1"));
}

#[tokio::test]
async fn accepts_both_google_issuer_forms() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), None).await;
    let svc = service(&idp);
    for iss in ["https://accounts.google.com", "accounts.google.com"] {
        let mut c = google_claims("s", "n", None, false);
        c["iss"] = json!(iss);
        assert!(svc.verify_id_token(Provider::Google, &cfg(None), &sign(&c)).await.is_ok(), "{iss}");
    }
}

#[tokio::test]
async fn rejects_tokens_with_bad_standard_claims() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), None).await;
    let svc = service(&idp);
    let now = Utc::now().timestamp();
    let cases: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
        ("wrong audience", Box::new(|c| c["aud"] = json!("someone-else"))),
        ("expired", Box::new(move |c| c["exp"] = json!(now - 3600))),
        ("foreign issuer", Box::new(|c| c["iss"] = json!("https://evil.example.com"))),
        ("missing exp", Box::new(|c| { c.as_object_mut().unwrap().remove("exp"); })),
        ("missing aud", Box::new(|c| { c.as_object_mut().unwrap().remove("aud"); })),
        ("missing sub", Box::new(|c| { c.as_object_mut().unwrap().remove("sub"); })),
        ("missing iss", Box::new(|c| { c.as_object_mut().unwrap().remove("iss"); })),
    ];
    for (name, mutate) in cases {
        let mut c = google_claims("s", "n", None, false);
        mutate(&mut c);
        let r = svc.verify_id_token(Provider::Google, &cfg(None), &sign(&c)).await;
        assert!(matches!(r, Err(AppError::Unauthorized(_))), "{name} should be rejected");
    }
}

#[tokio::test]
async fn accepts_audience_array_containing_client_id() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), None).await;
    let mut c = google_claims("s", "n", None, false);
    c["aud"] = json!(["other", CLIENT_ID]);
    assert!(service(&idp).verify_id_token(Provider::Google, &cfg(None), &sign(&c)).await.is_ok());
}

#[tokio::test]
async fn rejects_signature_from_a_different_key() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), None).await;
    // Signed by key B but claims to be key A.
    let token = sign_with(&google_claims("s", "n", None, false), KEY_B_PEM, Some(KID_A));
    let r = service(&idp).verify_id_token(Provider::Google, &cfg(None), &token).await;
    assert!(matches!(r, Err(AppError::Unauthorized(_))));
}

#[tokio::test]
async fn rejects_tampered_payload() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), None).await;
    let token = sign(&google_claims("victim", "n", None, false));
    let parts: Vec<&str> = token.split('.').collect();
    let forged = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&google_claims("attacker", "n", None, false)).unwrap(),
    );
    let tampered = format!("{}.{}.{}", parts[0], forged, parts[2]);
    let r = service(&idp).verify_id_token(Provider::Google, &cfg(None), &tampered).await;
    assert!(matches!(r, Err(AppError::Unauthorized(_))));
}

#[tokio::test]
async fn rejects_non_rs256_algorithms_before_fetching_keys() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), Some(0)).await;
    let svc = service(&idp);
    let claims = google_claims("s", "n", None, false);

    // HS256 keyed with the public JWKS — the classic algorithm-confusion attack.
    let mut header = jsonwebtoken::Header::new(Algorithm::HS256);
    header.kid = Some(KID_A.into());
    let hs = jsonwebtoken::encode(&header, &claims, &jsonwebtoken::EncodingKey::from_secret(JWKS_A.as_bytes())).unwrap();
    assert!(unauthorized_containing(
        svc.verify_id_token(Provider::Google, &cfg(None), &hs).await,
        "algorithm"
    ));

    // RS512 with a valid key is still refused: the algorithm is pinned, not negotiated.
    let mut header = jsonwebtoken::Header::new(Algorithm::RS512);
    header.kid = Some(KID_A.into());
    let rs512 = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(KEY_A_PEM.as_bytes()).unwrap(),
    )
    .unwrap();
    assert!(unauthorized_containing(
        svc.verify_id_token(Provider::Google, &cfg(None), &rs512).await,
        "algorithm"
    ));
}

#[tokio::test]
async fn rejects_unsigned_and_garbage_tokens() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), Some(0)).await;
    let svc = service(&idp);
    let none_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT","kid":"test-key-a"}"#);
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&google_claims("s", "n", None, false)).unwrap());
    for token in [format!("{none_header}.{body}."), "".into(), "a.b".into(), "not-a-jwt".into()] {
        let r = svc.verify_id_token(Provider::Google, &cfg(None), &token).await;
        assert!(matches!(r, Err(AppError::Unauthorized(_))), "{token:?}");
    }
}

#[tokio::test]
async fn rejects_token_without_kid() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), Some(0)).await;
    let token = sign_with(&google_claims("s", "n", None, false), KEY_A_PEM, None);
    let r = service(&idp).verify_id_token(Provider::Google, &cfg(None), &token).await;
    assert!(unauthorized_containing(r, "key id"));
}

// ---- ID-token verification: Microsoft -------------------------------------------------

#[tokio::test]
async fn verifies_valid_microsoft_token_from_authority_jwks() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(&ms_jwks_path("common"), jwks_a(), Some(1)).await;
    let token = sign(&microsoft_claims(MS_ORG_TID, "oid-1", "n", Some("g@contoso.com"), true));
    let c = service(&idp).verify_id_token(Provider::Microsoft, &cfg(None), &token).await.unwrap();
    assert_eq!(c.oid.as_deref(), Some("oid-1"));
}

#[tokio::test]
async fn microsoft_token_with_issuer_for_another_directory_is_rejected() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(&ms_jwks_path("common"), jwks_a(), None).await;
    let mut c = microsoft_claims(MS_ORG_TID, "oid", "n", None, false);
    c["iss"] = json!(format!("https://login.microsoftonline.com/{}/v2.0", MS_CONSUMERS_TID));
    let r = service(&idp).verify_id_token(Provider::Microsoft, &cfg(None), &sign(&c)).await;
    assert!(unauthorized_containing(r, "issuer"));
}

#[tokio::test]
async fn microsoft_directory_restriction_is_enforced_after_signature_check() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(&ms_jwks_path("organizations"), jwks_a(), None).await;
    let token = sign(&microsoft_claims(MS_CONSUMERS_TID, "oid", "n", None, false));
    let r = service(&idp)
        .verify_id_token(Provider::Microsoft, &cfg(Some("organizations")), &token)
        .await;
    assert!(matches!(r, Err(AppError::Forbidden(_))));
}

#[tokio::test]
async fn google_tokens_are_not_accepted_as_microsoft_tokens() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(&ms_jwks_path("common"), jwks_a(), None).await;
    let token = sign(&google_claims("s", "n", Some("a@gmail.com"), true));
    let r = service(&idp).verify_id_token(Provider::Microsoft, &cfg(None), &token).await;
    assert!(matches!(r, Err(AppError::Unauthorized(_))));
}

// ---- JWKS cache -----------------------------------------------------------------------

#[tokio::test]
async fn jwks_is_cached_across_verifications() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), Some(1)).await;
    let svc = service(&idp);
    for i in 0..5 {
        let t = sign(&google_claims(&format!("s{i}"), "n", None, false));
        svc.verify_id_token(Provider::Google, &cfg(None), &t).await.unwrap();
    }
}

#[tokio::test]
async fn jwks_cache_is_shared_between_service_clones() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), Some(1)).await;
    let svc = service(&idp);
    let clone = svc.clone();
    let t = sign(&google_claims("s", "n", None, false));
    svc.verify_id_token(Provider::Google, &cfg(None), &t).await.unwrap();
    clone.verify_id_token(Provider::Google, &cfg(None), &t).await.unwrap();
}

#[tokio::test]
async fn jwks_caches_are_per_endpoint() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), Some(1)).await;
    idp.serve_jwks(&ms_jwks_path("common"), jwks_b(), Some(1)).await;
    let svc = service(&idp);
    let g = sign(&google_claims("s", "n", None, false));
    let m = sign_with(&microsoft_claims(MS_ORG_TID, "o", "n", None, false), KEY_B_PEM, Some(KID_B));
    svc.verify_id_token(Provider::Google, &cfg(None), &g).await.unwrap();
    svc.verify_id_token(Provider::Microsoft, &cfg(None), &m).await.unwrap();
    // Key B is only published on the Microsoft endpoint.
    let g_with_b = sign_with(&google_claims("s", "n", None, false), KEY_B_PEM, Some(KID_B));
    assert!(svc.verify_id_token(Provider::Google, &cfg(None), &g_with_b).await.is_err());
}

#[tokio::test]
async fn unknown_kid_does_not_refetch_within_min_refresh_window() {
    let idp = MockIdp::start().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), Some(1)).await;
    let svc = service(&idp);
    svc.verify_id_token(Provider::Google, &cfg(None), &sign(&google_claims("s", "n", None, false)))
        .await
        .unwrap();
    // A flood of bogus kids must not hammer the provider.
    for i in 0..10 {
        let t = sign_with(&google_claims("s", "n", None, false), KEY_A_PEM, Some(&format!("bogus-{i}")));
        let r = svc.verify_id_token(Provider::Google, &cfg(None), &t).await;
        assert!(unauthorized_containing(r, "signing key"));
    }
}

#[tokio::test]
async fn unknown_kid_refetches_after_min_refresh_window_to_pick_up_rotation() {
    let idp = MockIdp::start().await;
    let svc = service(&idp);
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), Some(1)).await;
    svc.verify_id_token(Provider::Google, &cfg(None), &sign(&google_claims("s", "n", None, false)))
        .await
        .unwrap();

    // Provider rotates in key B.
    idp.server.reset().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_ab(), Some(1)).await;
    age_cache(&svc, &idp.google_jwks_url(), JWKS_MIN_REFRESH_SECS + 1);

    let t = sign_with(&google_claims("s", "n", None, false), KEY_B_PEM, Some(KID_B));
    svc.verify_id_token(Provider::Google, &cfg(None), &t).await.unwrap();
    // Old key still served from the refreshed cache.
    svc.verify_id_token(Provider::Google, &cfg(None), &sign(&google_claims("s", "n", None, false)))
        .await
        .unwrap();
}

#[tokio::test]
async fn stale_cache_is_refetched_even_for_known_kid() {
    let idp = MockIdp::start().await;
    let svc = service(&idp);
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), None).await;
    let t = sign(&google_claims("s", "n", None, false));
    svc.verify_id_token(Provider::Google, &cfg(None), &t).await.unwrap();

    // Provider retired key A; after the TTL the cache must not keep trusting it.
    idp.server.reset().await;
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_b(), Some(1)).await;
    age_cache(&svc, &idp.google_jwks_url(), JWKS_CACHE_TTL_SECS + 1);
    let r = svc.verify_id_token(Provider::Google, &cfg(None), &t).await;
    assert!(unauthorized_containing(r, "signing key"));
}

#[tokio::test]
async fn jwks_fetch_failures_are_internal_and_not_cached() {
    let idp = MockIdp::start().await;
    let svc = service(&idp);
    let t = sign(&google_claims("s", "n", None, false));

    Mock::given(method("GET"))
        .and(path(GOOGLE_JWKS_PATH))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&idp.server)
        .await;
    let r = svc.verify_id_token(Provider::Google, &cfg(None), &t).await;
    assert!(matches!(r, Err(AppError::Internal(ref m)) if m.contains("fetch")));

    Mock::given(method("GET"))
        .and(path(GOOGLE_JWKS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not json"))
        .up_to_n_times(1)
        .mount(&idp.server)
        .await;
    let r = svc.verify_id_token(Provider::Google, &cfg(None), &t).await;
    assert!(matches!(r, Err(AppError::Internal(ref m)) if m.contains("Invalid provider signing keys")));

    // Failures leave no cache entry, so the next attempt fetches again and succeeds.
    idp.serve_jwks(GOOGLE_JWKS_PATH, jwks_a(), None).await;
    svc.verify_id_token(Provider::Google, &cfg(None), &t).await.unwrap();
}
