//! Route mounting.

use axum::Router;

use crate::api::state::AppState;
use std::sync::Arc;

pub mod auth;
pub mod mfa;
pub mod session;
pub mod admin;
pub mod health;
pub mod spec;
pub mod platform;
pub mod packages;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .merge(spec::router())
        .merge(health::router())
        .merge(auth::signup_router())
        .merge(auth::password_router())
        .nest("/login", auth::router())
        .nest("/oauth", auth::oauth_router())
        .nest("/mfa", mfa::router())
        .nest("/session", session::router())
        .nest("/admin", admin::router())
        .nest("/admin", packages::router())
        .merge(platform::router())
}