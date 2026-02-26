//! User identity types and validation.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Uuid,
    #[serde(skip_serializing)]
    pub tenant_id: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub username: Option<String>,
    pub mobile: Option<String>,
    pub country_code: Option<String>,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub status: String,
    pub mfa_enabled: bool,
    pub failed_attempts: i32,
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Identity rule: at least one of email, (mobile AND country_code), or username must exist.
pub fn has_valid_identity(
    email: &Option<String>,
    mobile: &Option<String>,
    country_code: &Option<String>,
    username: &Option<String>,
) -> bool {
    let has_email = email.as_ref().map_or(false, |e| !e.is_empty());
    let has_mobile = mobile
        .as_ref()
        .zip(country_code.as_ref())
        .map_or(false, |(m, c)| !m.is_empty() && !c.is_empty());
    let has_username = username.as_ref().map_or(false, |u| !u.is_empty());
    has_email || has_mobile || has_username
}
