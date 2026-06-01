//! RBAC: roles, permissions, groups.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub uid: String,
    pub parent_role_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Permission {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub uid: String,
    pub description: Option<String>,
}
