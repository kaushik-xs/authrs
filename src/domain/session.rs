//! Session payload for Redis/DB.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPayload {
    pub tenant_id: String,
    pub user_id: Uuid,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}
