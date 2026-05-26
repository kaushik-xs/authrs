//! Session payload for Redis/DB.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPayload {
    pub tenant_id: String,
    pub user_id: Uuid,
    /// Role UIDs (slug strings) — used for Cedar entity hierarchy.
    pub roles: Vec<String>,
    /// Role primary-key UUIDs — used for role-scoped PolicySet loading.
    #[serde(default)]
    pub role_ids: Vec<Uuid>,
    pub permissions: Vec<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}
