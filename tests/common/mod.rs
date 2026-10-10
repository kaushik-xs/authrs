//! Shared harness for the database-backed integration and HTTP end-to-end tests.
//!
//! Each `#[sqlx::test]` gets its own freshly migrated database (created from the server in
//! `DATABASE_URL`, read from the environment or `.env`), so tests are isolated and can run
//! in parallel.
#![allow(dead_code)]

pub mod mock_idp;

use authrs::api::state::AppState;
use authrs::repo::oauth::OauthRepo;
use authrs::repo::kv_store::KvStoreRepo;
use authrs::services::oauth::{OauthService, ProviderEndpoints};
use authrs::services::tenant_config::TenantConfigLoader;
use mock_idp::MockIdp;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub const TENANT: &str = "acme";
pub const OTHER_TENANT: &str = "globex";

/// AppState wired like production (Postgres sessions, no Redis/SMTP).
pub fn app_state(pool: &PgPool) -> AppState {
    AppState::new(
        pool.clone(),
        None,
        None,
        None,
        None,
        "builder".to_string(),
        vec![],
        3600,
        "Authrs".to_string(),
    )
    .expect("AppState")
}

/// AppState whose OAuth service talks to `idp` instead of Google / Microsoft.
pub fn app_state_with_idp(pool: &PgPool, idp: &MockIdp) -> Arc<AppState> {
    let mut state = app_state(pool);
    state.oauth_service = oauth_service(pool, idp);
    Arc::new(state)
}

pub fn oauth_service(pool: &PgPool, idp: &MockIdp) -> OauthService {
    OauthService::with_endpoints(
        OauthRepo::new(pool.clone()),
        TenantConfigLoader::new(KvStoreRepo::new(pool.clone(), None).unwrap()),
        ProviderEndpoints {
            google_auth_url: idp.google_auth_url(),
            google_token_url: idp.google_token_url(),
            google_jwks_url: idp.google_jwks_url(),
            microsoft_login_base: idp.microsoft_base(),
        },
    )
    .unwrap()
}

pub async fn create_tenant(pool: &PgPool, id: &str) {
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $1)")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

/// Write a plain (non-sensitive) kv_store value, as the admin API would.
pub async fn set_kv(pool: &PgPool, tenant: &str, group: &str, key: &str, value: Value) {
    KvStoreRepo::new(pool.clone(), None)
        .unwrap()
        .set(tenant, group, key, &value, false)
        .await
        .unwrap();
}

pub async fn create_identity(pool: &PgPool, email: Option<&str>) -> Uuid {
    sqlx::query_scalar("INSERT INTO identities (email) VALUES ($1) RETURNING id")
        .bind(email)
        .fetch_one(pool)
        .await
        .unwrap()
}

pub async fn create_membership(pool: &PgPool, identity_id: Uuid, tenant: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO users (id, tenant_id, identity_id, status) VALUES (gen_random_uuid(), $1, $2, 'active') RETURNING id",
    )
    .bind(tenant)
    .bind(identity_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

pub async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

pub async fn link_count(pool: &PgPool) -> i64 {
    count(pool, "SELECT count(*) FROM identity_oauth_accounts").await
}

pub async fn identity_count(pool: &PgPool) -> i64 {
    count(pool, "SELECT count(*) FROM identities").await
}

pub async fn membership_count(pool: &PgPool) -> i64 {
    count(pool, "SELECT count(*) FROM users").await
}
