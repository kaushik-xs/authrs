//! MFA routes: enable, verify, validate.

use axum::{routing::post, Router};

use crate::api::state::AppState;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/enable", post(mfa_enable))
        .route("/verify", post(mfa_verify))
        .route("/validate", post(mfa_validate))
}

async fn mfa_enable() -> &'static str {
    "mfa enable placeholder"
}

async fn mfa_verify() -> &'static str {
    "mfa verify placeholder"
}

async fn mfa_validate() -> &'static str {
    "mfa validate placeholder"
}