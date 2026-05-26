//! Session payload for Redis/DB.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPayload {
    pub tenant_id: String,
    pub user_id: Uuid,
    /// Effective role UIDs (direct + inherited through groups) — Cedar entity hierarchy.
    pub roles: Vec<String>,
    /// Effective role primary-key UUIDs (direct + via groups) — role-scoped PolicySet loading.
    #[serde(default)]
    pub role_ids: Vec<Uuid>,
    pub permissions: Vec<String>,
    /// Group UIDs the user belongs to — Cedar `principal in UserGroup::""` policies.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Group primary-key UUIDs — used for admin lookups and group-scoped policy loading.
    #[serde(default)]
    pub group_ids: Vec<Uuid>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}
