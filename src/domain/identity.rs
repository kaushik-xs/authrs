//! Global identity types. An identity is "who you are" across all tenants: the login
//! handles (email, mobile) and credentials (password, MFA, lockout) shared by every
//! tenant membership of the same human. Per-tenant facts live on the membership
//! (`crate::domain::user::User`), which references an identity via `identity_id`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub id: Uuid,
    pub email: Option<String>,
    pub mobile: Option<String>,
    pub country_code: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub mfa_enabled: bool,
    #[serde(skip_serializing)]
    pub mfa_secret: Option<String>,
    pub force_password_change: bool,
    pub failed_attempts: i32,
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Global account kill-switch (distinct from the per-tenant membership status).
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// An identity must be reachable by at least one global login handle (email or
/// mobile+country_code) OR by a per-tenant username on one of its memberships. The
/// handle-only part is checked here; the username fallback is enforced where membership
/// context is available (signup/admin-create). A handle-less identity is a username-only
/// (local, single-tenant) account.
pub fn has_global_handle(
    email: &Option<String>,
    mobile: &Option<String>,
    country_code: &Option<String>,
) -> bool {
    let has_email = email.as_ref().map_or(false, |e| !e.is_empty());
    let has_mobile = mobile
        .as_ref()
        .zip(country_code.as_ref())
        .map_or(false, |(m, c)| !m.is_empty() && !c.is_empty());
    has_email || has_mobile
}
