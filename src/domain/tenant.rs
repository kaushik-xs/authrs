//! Tenant domain type.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
