//! RBAC: roles, permissions (roles assigned only to users).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Permission {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
}
