//! Permission document domain types — the JSON format stored in the permissions table.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionDocument {
    pub version: String,
    pub statements: Vec<PermissionStatement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionStatement {
    pub sid: String,
    pub effect: Effect,
    /// Accepted formats: "role:<uuid>", "role:<name>", "user:<uuid>",
    /// "user:<email>", "user:<username>", "*"
    /// All non-UUID values are resolved to UUIDs before the document is stored.
    pub principals: Vec<String>,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    /// e.g. "context.tls_version", "context.mfa_verified"
    pub attribute: String,
    /// "eq" | "neq" | "gt" | "lt"
    pub operator: String,
    pub value: serde_json::Value,
}
