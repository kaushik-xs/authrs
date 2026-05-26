//! Compiles a PermissionDocument into a cedar_policy::PolicySet.
//! One Cedar policy object is emitted per (statement × principal × action × resource).

use cedar_policy::{Policy, PolicyId, PolicySet};
use serde_json::json;

use crate::error::AppError;
use crate::policy::domain::{Condition, Effect, PermissionDocument, PermissionStatement};

pub fn compile(doc: &PermissionDocument, permission_db_id: &str) -> Result<PolicySet, AppError> {
    let mut set = PolicySet::new();

    for stmt in &doc.statements {
        for principal in &stmt.principals {
            for action in &stmt.actions {
                for resource in &stmt.resources {
                    let id = PolicyId::new(format!(
                        "{permission_db_id}-{}-{action}-{resource}",
                        stmt.sid
                    ));
                    let cedar_json =
                        build_cedar_json(stmt, principal, action, resource);
                    let policy = Policy::from_json(Some(id), cedar_json)
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    set.add(policy)
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                }
            }
        }
    }

    Ok(set)
}

fn build_cedar_json(
    stmt: &PermissionStatement,
    principal: &str,
    action: &str,
    resource: &str,
) -> serde_json::Value {
    let effect = match stmt.effect {
        Effect::Allow => "permit",
        Effect::Deny => "forbid",
    };
    let principal_clause = parse_principal(principal);
    let resource_clause = parse_resource(resource);
    let conditions = build_conditions(&stmt.conditions);

    json!({
        "effect": effect,
        "principal": principal_clause,
        "action": {
            "op": "==",
            "entity": { "type": "AuthRS::Action", "id": action }
        },
        "resource": resource_clause,
        "conditions": conditions
    })
}

/// "role:<uuid>"    → { op: "in",  entity: { type: "AuthRS::Role", id: "<uuid>" } }
/// "user:<uuid>"    → { op: "==", entity: { type: "AuthRS::User", id: "<uuid>" } }
/// "*"              → { op: "All" }
fn parse_principal(principal: &str) -> serde_json::Value {
    if principal == "*" {
        return json!({ "op": "All" });
    }
    let (prefix, id) = principal
        .split_once(':')
        .unwrap_or(("user", principal));
    let (op, entity_type) = match prefix {
        "role" => ("in", "AuthRS::Role"),
        _ => ("==", "AuthRS::User"),
    };
    json!({ "op": op, "entity": { "type": entity_type, "id": id } })
}

/// "service:core/package:manufacturing_core/table:materials/column:material_name"
/// → { op: "==", entity: { type: "Column", id: "core/manufacturing_core/materials/material_name" } }
fn parse_resource(resource: &str) -> serde_json::Value {
    let segments: Vec<&str> = resource.split('/').collect();
    let last = segments.last().copied().unwrap_or(resource);
    let entity_type = if last.starts_with("column:") {
        "AuthRS::Column"
    } else if last.starts_with("table:") {
        "AuthRS::Table"
    } else if last.starts_with("package:") {
        "AuthRS::Package"
    } else {
        "AuthRS::Service"
    };

    // Strip the type prefix from each segment to build the canonical id
    let id = segments
        .iter()
        .map(|s| s.splitn(2, ':').nth(1).unwrap_or(s))
        .collect::<Vec<_>>()
        .join("/");

    json!({ "op": "==", "entity": { "type": entity_type, "id": id } })
}

fn build_conditions(conditions: &[Condition]) -> serde_json::Value {
    if conditions.is_empty() {
        return json!([]);
    }

    let exprs: Vec<serde_json::Value> = conditions
        .iter()
        .map(|c| {
            let op = match c.operator.as_str() {
                "neq" => "!=",
                "gt" => ">",
                "lt" => "<",
                _ => "==",
            };
            let attr = c.attribute.trim_start_matches("context.");
            json!({
                "kind": "when",
                "body": {
                    op: [
                        { "Var": attr },
                        { "Value": c.value }
                    ]
                }
            })
        })
        .collect();

    json!(exprs)
}
