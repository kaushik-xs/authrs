//! Integration tests: OauthRepo against a real Postgres (one migrated database per test).
//! Covers single-use / expiring authorization states and provider-account linking.

mod common;

use authrs::repo::oauth::OauthRepo;
use authrs::AppError;
use chrono::{Duration, Utc};
use common::*;
use sqlx::PgPool;

async fn put_state(repo: &OauthRepo, state: &str, expires_in: Duration) {
    repo.create_state(state, TENANT, "google", "verifier", "nonce", Utc::now() + expires_in)
        .await
        .unwrap();
}

async fn state_rows(pool: &PgPool) -> i64 {
    count(pool, "SELECT count(*) FROM oauth_states").await
}

// ---- Authorization states -------------------------------------------------------------

#[sqlx::test]
async fn take_state_returns_what_was_stored(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    repo.create_state("s1", TENANT, "microsoft", "the-verifier", "the-nonce", Utc::now() + Duration::minutes(10))
        .await
        .unwrap();
    let st = repo.take_state("s1").await.unwrap().expect("state");
    assert_eq!(st.tenant_id, TENANT);
    assert_eq!(st.provider, "microsoft");
    assert_eq!(st.pkce_verifier, "the-verifier");
    assert_eq!(st.nonce, "the-nonce");
}

#[sqlx::test]
async fn state_is_single_use(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    put_state(&repo, "s1", Duration::minutes(10)).await;
    assert!(repo.take_state("s1").await.unwrap().is_some());
    assert!(repo.take_state("s1").await.unwrap().is_none(), "replay must fail");
    assert_eq!(state_rows(&pool).await, 0);
}

#[sqlx::test]
async fn unknown_state_is_none(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    put_state(&repo, "s1", Duration::minutes(10)).await;
    assert!(repo.take_state("nope").await.unwrap().is_none());
    assert!(repo.take_state("").await.unwrap().is_none());
    assert!(repo.take_state("S1").await.unwrap().is_none(), "lookup is exact");
    assert_eq!(state_rows(&pool).await, 1, "a miss must not consume other states");
}

#[sqlx::test]
async fn expired_state_cannot_be_taken(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    put_state(&repo, "old", Duration::seconds(-1)).await;
    assert!(repo.take_state("old").await.unwrap().is_none());
}

#[sqlx::test]
async fn creating_a_state_purges_expired_ones_only(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    // Insert directly so the cleanup in create_state doesn't run between them.
    for (s, mins) in [("old1", -30), ("old2", -1), ("live", 5)] {
        sqlx::query(
            "INSERT INTO oauth_states (state, tenant_id, provider, pkce_verifier, nonce, expires_at) \
             VALUES ($1, 'acme', 'google', 'v', 'n', now() + make_interval(mins => $2))",
        )
        .bind(s)
        .bind(mins)
        .execute(&pool)
        .await
        .unwrap();
    }
    put_state(&repo, "new", Duration::minutes(10)).await;
    let mut left: Vec<String> = sqlx::query_scalar("SELECT state FROM oauth_states")
        .fetch_all(&pool)
        .await
        .unwrap();
    left.sort();
    assert_eq!(left, vec!["live", "new"]);
}

#[sqlx::test]
async fn duplicate_state_is_rejected(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    put_state(&repo, "dup", Duration::minutes(10)).await;
    let r = repo
        .create_state("dup", OTHER_TENANT, "google", "v2", "n2", Utc::now() + Duration::minutes(10))
        .await;
    assert!(matches!(r, Err(AppError::Conflict(_))), "a state value must never be reused");
    // The original is untouched.
    assert_eq!(repo.take_state("dup").await.unwrap().unwrap().tenant_id, TENANT);
}

#[sqlx::test]
async fn concurrent_takes_redeem_a_state_exactly_once(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    put_state(&repo, "race", Duration::minutes(10)).await;
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let repo = repo.clone();
            tokio::spawn(async move { repo.take_state("race").await.unwrap() })
        })
        .collect();
    let mut wins = 0;
    for h in handles {
        if h.await.unwrap().is_some() {
            wins += 1;
        }
    }
    assert_eq!(wins, 1);
}

// ---- Provider-account links -----------------------------------------------------------

#[sqlx::test]
async fn link_and_resolve_identity(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    let id = create_identity(&pool, Some("a@example.com")).await;
    assert!(repo.get_linked_identity("google", "sub-1").await.unwrap().is_none());
    repo.link(id, "google", "sub-1", Some("a@example.com")).await.unwrap();
    assert_eq!(repo.get_linked_identity("google", "sub-1").await.unwrap(), Some(id));
}

#[sqlx::test]
async fn links_are_scoped_by_provider(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    let a = create_identity(&pool, None).await;
    let b = create_identity(&pool, None).await;
    repo.link(a, "google", "same-subject", None).await.unwrap();
    repo.link(b, "microsoft", "same-subject", None).await.unwrap();
    assert_eq!(repo.get_linked_identity("google", "same-subject").await.unwrap(), Some(a));
    assert_eq!(repo.get_linked_identity("microsoft", "same-subject").await.unwrap(), Some(b));
}

#[sqlx::test]
async fn an_identity_may_link_several_providers(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    let id = create_identity(&pool, None).await;
    repo.link(id, "google", "g-sub", None).await.unwrap();
    repo.link(id, "microsoft", "tid:oid", None).await.unwrap();
    assert_eq!(repo.get_linked_identity("google", "g-sub").await.unwrap(), Some(id));
    assert_eq!(repo.get_linked_identity("microsoft", "tid:oid").await.unwrap(), Some(id));
}

#[sqlx::test]
async fn a_provider_account_maps_to_one_identity(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    let a = create_identity(&pool, None).await;
    let b = create_identity(&pool, None).await;
    repo.link(a, "google", "sub", None).await.unwrap();
    let r = repo.link(b, "google", "sub", None).await;
    assert!(matches!(r, Err(AppError::Conflict(_))), "got {r:?}");
    assert_eq!(repo.get_linked_identity("google", "sub").await.unwrap(), Some(a));
}

#[sqlx::test]
async fn links_are_removed_with_their_identity(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    let id = create_identity(&pool, None).await;
    repo.link(id, "google", "sub", None).await.unwrap();
    sqlx::query("DELETE FROM identities WHERE id = $1").bind(id).execute(&pool).await.unwrap();
    assert!(repo.get_linked_identity("google", "sub").await.unwrap().is_none());
}

#[sqlx::test]
async fn linking_requires_an_existing_identity(pool: PgPool) {
    let repo = OauthRepo::new(pool.clone());
    assert!(repo.link(uuid::Uuid::new_v4(), "google", "sub", None).await.is_err());
}
