//! Integration tests: `AuthService::login_oauth` against a real Postgres. Exercises every
//! account-resolution branch (linked account / verified-email auto-link / new identity),
//! membership provisioning, tenant policy and the shared login gates.

mod common;

use authrs::api::state::AppState;
use authrs::services::auth::LoginResult;
use authrs::services::oauth::OauthProfile;
use authrs::AppError;
use common::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn profile(sub: &str, email: Option<&str>, verified: bool) -> OauthProfile {
    OauthProfile {
        provider_user_id: sub.to_string(),
        email: email.map(String::from),
        email_verified: verified,
        first_name: Some("Ada".into()),
        last_name: Some("Lovelace".into()),
    }
}

async fn setup(pool: &PgPool) -> AppState {
    create_tenant(pool, TENANT).await;
    create_tenant(pool, OTHER_TENANT).await;
    app_state(pool)
}

async fn login(
    state: &AppState,
    tenant: &str,
    p: &OauthProfile,
    allow_signup: bool,
) -> Result<LoginResult, AppError> {
    state.auth_service.login_oauth(tenant, "google", p, allow_signup, Some("127.0.0.1"), Some("test")).await
}

fn assert_success(r: Result<LoginResult, AppError>) -> String {
    match r {
        Ok(LoginResult::Success { session_token, .. }) => session_token,
        Ok(_) => panic!("expected a session, got another login step"),
        Err(e) => panic!("expected success, got {e}"),
    }
}

fn assert_forbidden(r: Result<LoginResult, AppError>, needle: &str) {
    match r {
        Err(AppError::Forbidden(m)) => assert!(m.contains(needle), "message {m:?} lacks {needle:?}"),
        Err(e) => panic!("expected Forbidden({needle}), got {e}"),
        Ok(_) => panic!("expected Forbidden({needle}), got success"),
    }
}

async fn linked_identity(pool: &PgPool, sub: &str) -> Option<Uuid> {
    sqlx::query_scalar("SELECT identity_id FROM identity_oauth_accounts WHERE provider = 'google' AND provider_user_id = $1")
        .bind(sub)
        .fetch_optional(pool)
        .await
        .unwrap()
}

// ---- First sign-in --------------------------------------------------------------------

#[sqlx::test]
async fn first_sign_in_creates_identity_link_membership_and_session(pool: PgPool) {
    let state = setup(&pool).await;
    let token = assert_success(login(&state, TENANT, &profile("g-1", Some("ada@example.com"), true), true).await);

    let identity = linked_identity(&pool, "g-1").await.expect("link created");
    let (email, first, pw): (Option<String>, Option<String>, Option<String>) =
        sqlx::query_as("SELECT email, first_name, password_hash FROM identities WHERE id = $1")
            .bind(identity)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(email.as_deref(), Some("ada@example.com"));
    assert_eq!(first.as_deref(), Some("Ada"));
    assert!(pw.is_none(), "social-only identity has no password");

    let session = state.session_store.get(&token).await.unwrap().expect("session stored");
    assert_eq!(session.tenant_id, TENANT);
    assert_eq!(session.identity_id, identity);
    assert_eq!(session.ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(membership_count(&pool).await, 1);
}

#[sqlx::test]
async fn repeat_sign_in_reuses_identity_and_membership(pool: PgPool) {
    let state = setup(&pool).await;
    let p = profile("g-1", Some("ada@example.com"), true);
    let t1 = assert_success(login(&state, TENANT, &p, true).await);
    let t2 = assert_success(login(&state, TENANT, &p, true).await);
    assert_ne!(t1, t2, "each login gets a fresh session");
    assert_eq!(identity_count(&pool).await, 1);
    assert_eq!(link_count(&pool).await, 1);
    assert_eq!(membership_count(&pool).await, 1);
}

#[sqlx::test]
async fn linked_account_is_found_even_if_provider_email_changes(pool: PgPool) {
    let state = setup(&pool).await;
    assert_success(login(&state, TENANT, &profile("g-1", Some("old@example.com"), true), true).await);
    assert_success(login(&state, TENANT, &profile("g-1", Some("new@example.com"), true), true).await);
    assert_eq!(identity_count(&pool).await, 1);
}

// ---- Auto-linking by email ------------------------------------------------------------

#[sqlx::test]
async fn verified_email_links_to_existing_identity(pool: PgPool) {
    let state = setup(&pool).await;
    let existing = create_identity(&pool, Some("Ada@Example.com")).await;
    create_membership(&pool, existing, TENANT).await;

    assert_success(login(&state, TENANT, &profile("g-1", Some("ada@example.com"), true), true).await);
    assert_eq!(linked_identity(&pool, "g-1").await, Some(existing), "case-insensitive match");
    assert_eq!(identity_count(&pool).await, 1);
    assert_eq!(membership_count(&pool).await, 1);
}

#[sqlx::test]
async fn unverified_email_never_attaches_to_existing_identity(pool: PgPool) {
    let state = setup(&pool).await;
    let victim = create_identity(&pool, Some("victim@example.com")).await;
    create_membership(&pool, victim, TENANT).await;

    assert_forbidden(
        login(&state, TENANT, &profile("attacker", Some("victim@example.com"), false), true).await,
        "already exists",
    );
    assert_eq!(link_count(&pool).await, 0);
    assert_eq!(identity_count(&pool).await, 1);
}

#[sqlx::test]
async fn unverified_email_creates_handle_less_identity(pool: PgPool) {
    let state = setup(&pool).await;
    assert_success(login(&state, TENANT, &profile("ms-1", Some("someone@corp.example"), false), true).await);
    let identity = linked_identity(&pool, "ms-1").await.unwrap();
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM identities WHERE id = $1")
        .bind(identity)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(email.is_none(), "an unverified email must not claim the global handle");
    let asserted: Option<String> =
        sqlx::query_scalar("SELECT email FROM identity_oauth_accounts WHERE provider_user_id = 'ms-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(asserted.as_deref(), Some("someone@corp.example"), "kept for audit on the link");
}

#[sqlx::test]
async fn sign_in_without_any_email_works(pool: PgPool) {
    let state = setup(&pool).await;
    assert_success(login(&state, TENANT, &profile("g-1", None, false), true).await);
    assert_eq!(link_count(&pool).await, 1);
}

// ---- Signup policy --------------------------------------------------------------------

#[sqlx::test]
async fn signup_disabled_rejects_unknown_accounts_without_side_effects(pool: PgPool) {
    let state = setup(&pool).await;
    assert_forbidden(
        login(&state, TENANT, &profile("g-1", Some("new@example.com"), true), false).await,
        "No account",
    );
    assert_eq!(identity_count(&pool).await, 0);
    assert_eq!(link_count(&pool).await, 0);
    assert_eq!(membership_count(&pool).await, 0);
}

#[sqlx::test]
async fn signup_disabled_still_admits_existing_members(pool: PgPool) {
    let state = setup(&pool).await;
    let id = create_identity(&pool, Some("member@example.com")).await;
    create_membership(&pool, id, TENANT).await;
    assert_success(login(&state, TENANT, &profile("g-1", Some("member@example.com"), true), false).await);
    assert_eq!(linked_identity(&pool, "g-1").await, Some(id));
}

#[sqlx::test]
async fn signup_disabled_rejects_identity_without_membership_here(pool: PgPool) {
    let state = setup(&pool).await;
    let p = profile("g-1", Some("ada@example.com"), true);
    assert_success(login(&state, OTHER_TENANT, &p, true).await);
    assert_forbidden(login(&state, TENANT, &p, false).await, "No membership");
    assert_eq!(membership_count(&pool).await, 1);
}

#[sqlx::test]
async fn same_identity_joins_a_second_tenant(pool: PgPool) {
    let state = setup(&pool).await;
    let p = profile("g-1", Some("ada@example.com"), true);
    let t1 = assert_success(login(&state, TENANT, &p, true).await);
    let t2 = assert_success(login(&state, OTHER_TENANT, &p, true).await);
    let s1 = state.session_store.get(&t1).await.unwrap().unwrap();
    let s2 = state.session_store.get(&t2).await.unwrap().unwrap();
    assert_eq!(s1.identity_id, s2.identity_id, "one global identity");
    assert_ne!(s1.user_id, s2.user_id, "one membership per tenant");
    assert_eq!(identity_count(&pool).await, 1);
    assert_eq!(membership_count(&pool).await, 2);
}

// ---- Tenant policy --------------------------------------------------------------------

#[sqlx::test]
async fn email_domain_allowlist_is_enforced_on_verified_email(pool: PgPool) {
    let state = setup(&pool).await;
    set_kv(&pool, TENANT, "email_policy", "allowed_domains", json!(["example.com"])).await;
    assert_success(login(&state, TENANT, &profile("ok", Some("a@EXAMPLE.com"), true), true).await);
    assert_forbidden(
        login(&state, TENANT, &profile("bad", Some("a@other.com"), true), true).await,
        "domain",
    );
    assert!(linked_identity(&pool, "bad").await.is_none());
}

#[sqlx::test]
async fn email_domain_allowlist_requires_a_verified_email(pool: PgPool) {
    let state = setup(&pool).await;
    set_kv(&pool, TENANT, "email_policy", "allowed_domains", json!(["example.com"])).await;
    // An unverified address on an allowed domain proves nothing.
    assert_forbidden(
        login(&state, TENANT, &profile("u", Some("a@example.com"), false), true).await,
        "verified email",
    );
    assert_forbidden(login(&state, TENANT, &profile("n", None, false), true).await, "verified email");
    assert_eq!(identity_count(&pool).await, 0);
}

#[sqlx::test]
async fn empty_allowlist_permits_everyone(pool: PgPool) {
    let state = setup(&pool).await;
    set_kv(&pool, TENANT, "email_policy", "allowed_domains", json!([])).await;
    assert_success(login(&state, TENANT, &profile("u", None, false), true).await);
}

#[sqlx::test]
async fn tenant_can_disable_oauth_login_method(pool: PgPool) {
    let state = setup(&pool).await;
    set_kv(&pool, TENANT, "login_methods", "allowed", json!([1, 2])).await;
    assert_forbidden(
        login(&state, TENANT, &profile("g-1", Some("a@example.com"), true), true).await,
        "OAuth login is not allowed",
    );
}

// ---- Shared gates ---------------------------------------------------------------------

async fn existing_member(pool: &PgPool, email: &str) -> (Uuid, Uuid) {
    let id = create_identity(pool, Some(email)).await;
    let user = create_membership(pool, id, TENANT).await;
    (id, user)
}

#[sqlx::test]
async fn inactive_identity_is_rejected(pool: PgPool) {
    let state = setup(&pool).await;
    let (id, _) = existing_member(&pool, "a@example.com").await;
    sqlx::query("UPDATE identities SET status = 'disabled' WHERE id = $1").bind(id).execute(&pool).await.unwrap();
    assert_forbidden(login(&state, TENANT, &profile("g", Some("a@example.com"), true), true).await, "not active");
}

#[sqlx::test]
async fn inactive_membership_is_rejected(pool: PgPool) {
    let state = setup(&pool).await;
    let (_, user) = existing_member(&pool, "a@example.com").await;
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1").bind(user).execute(&pool).await.unwrap();
    assert_forbidden(login(&state, TENANT, &profile("g", Some("a@example.com"), true), true).await, "not active");
}

#[sqlx::test]
async fn locked_identity_is_rejected(pool: PgPool) {
    let state = setup(&pool).await;
    let (id, _) = existing_member(&pool, "a@example.com").await;
    sqlx::query("UPDATE identities SET locked_until = now() + interval '5 minutes' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let r = login(&state, TENANT, &profile("g", Some("a@example.com"), true), true).await;
    assert!(matches!(r, Err(AppError::Locked(_))));
}

#[sqlx::test]
async fn expired_access_is_rejected(pool: PgPool) {
    let state = setup(&pool).await;
    let (_, user) = existing_member(&pool, "a@example.com").await;
    sqlx::query("UPDATE users SET access_valid_until = now() - interval '1 day' WHERE id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let r = login(&state, TENANT, &profile("g", Some("a@example.com"), true), true).await;
    assert!(matches!(r, Err(AppError::AccessExpired(_))));
}

#[sqlx::test]
async fn mfa_enabled_identity_gets_mfa_step_not_session(pool: PgPool) {
    let state = setup(&pool).await;
    let (id, _) = existing_member(&pool, "a@example.com").await;
    sqlx::query("UPDATE identities SET mfa_enabled = true WHERE id = $1").bind(id).execute(&pool).await.unwrap();
    let r = login(&state, TENANT, &profile("g", Some("a@example.com"), true), true).await;
    assert!(matches!(r, Ok(LoginResult::MfaRequired { .. })), "OAuth must not bypass MFA");
}

#[sqlx::test]
async fn force_password_change_is_honoured(pool: PgPool) {
    let state = setup(&pool).await;
    let (id, _) = existing_member(&pool, "a@example.com").await;
    sqlx::query("UPDATE identities SET force_password_change = true WHERE id = $1").bind(id).execute(&pool).await.unwrap();
    let r = login(&state, TENANT, &profile("g", Some("a@example.com"), true), true).await;
    assert!(matches!(r, Ok(LoginResult::PasswordChangeRequired { .. })));
}
