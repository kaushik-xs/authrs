//! Cedar authorization engine: builds entities and evaluates requests.

use std::collections::{HashMap, HashSet};

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityUid, PolicySet, Request,
    RestrictedExpression, Schema,
};
use uuid::Uuid;

use crate::policy::resource;
use crate::policy::schema::to_pascal_case;

pub struct AuthzRequest<'a> {
    pub user_id: Uuid,
    /// Role uids taken from the session (direct + ancestors already expanded).
    pub role_names: &'a [String],
    /// Derived action name e.g. "patchMaterials" or a custom action
    pub action: &'a str,
    /// Hierarchical resource path e.g. "service:core/package:manufacturing_core/table:materials"
    pub resource: &'a str,
    pub context: serde_json::Value,
}

pub fn authorize(req: &AuthzRequest, policy_set: &PolicySet, schema: &Schema) -> Decision {
    let principal_uid = user_uid(req.user_id);
    let resource_uid = match resource_root_uid(req.resource) {
        Ok(uid) => uid,
        Err(_) => {
            tracing::warn!(
                user_id = %req.user_id,
                resource = %req.resource,
                "deny: failed to parse resource UID"
            );
            return Decision::Deny;
        }
    };
    let action_uid = match action_uid(req.action) {
        Ok(uid) => uid,
        Err(_) => {
            tracing::warn!(
                user_id = %req.user_id,
                action = %req.action,
                "deny: failed to parse action UID"
            );
            return Decision::Deny;
        }
    };

    let mut all_entities = build_resource_chain(req.resource);
    all_entities.push(build_user_entity(req.user_id, req.role_names));

    let entities =
        Entities::from_entities(all_entities, Some(schema)).unwrap_or_else(|e| {
            tracing::warn!(
                user_id = %req.user_id,
                error = %e,
                "entity graph build failed, falling back to empty entities"
            );
            Entities::empty()
        });

    let ctx = Context::from_json_value(req.context.clone(), None)
        .unwrap_or_else(|e| {
            tracing::warn!(
                user_id = %req.user_id,
                error = %e,
                "context parse failed, falling back to empty context"
            );
            Context::empty()
        });

    let request = match Request::new(principal_uid, action_uid, resource_uid, ctx, Some(schema)) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                user_id = %req.user_id,
                resource = %req.resource,
                action = %req.action,
                error = %e,
                "deny: failed to build Cedar request"
            );
            return Decision::Deny;
        }
    };

    let decision = Authorizer::new()
        .is_authorized(&request, policy_set, &entities)
        .decision();

    tracing::debug!(
        user_id = %req.user_id,
        resource = %req.resource,
        action = %req.action,
        allowed = matches!(decision, Decision::Allow),
        "cedar authorization decision"
    );

    decision
}

/// Derives the Cedar action name from an HTTP verb and a resource path.
/// PATCH + "service:core/package:manufacturing_core/table:materials" → "patchMaterials"
/// Returns None if no table segment is found (caller should use custom action name instead).
pub fn derive_action_name(http_method: &str, resource_path: &str) -> Option<String> {
    let verb = http_method.to_lowercase();
    for segment in resource_path.split('/').rev() {
        if let Some(table_name) = segment.strip_prefix("table:") {
            return Some(format!("{}{}", verb, to_pascal_case(table_name)));
        }
    }
    None
}

fn user_uid(id: Uuid) -> EntityUid {
    format!("AuthRS::User::\"{}\"", id).parse().unwrap()
}

fn action_uid(verb: &str) -> Result<EntityUid, ()> {
    format!("AuthRS::Action::\"{}\"", verb)
        .parse()
        .map_err(|_| ())
}

fn resource_root_uid(resource_path: &str) -> Result<EntityUid, ()> {
    let segments: Vec<&str> = resource_path.split('/').collect();
    resource_uid(resource::entity_type(resource_path), &resource::entity_id(&segments))
}

fn resource_uid(entity_type: &str, id: &str) -> Result<EntityUid, ()> {
    format!("AuthRS::{}::\"{}\"", entity_type, id)
        .parse()
        .map_err(|_| ())
}

fn build_user_entity(user_id: Uuid, role_names: &[String]) -> Entity {
    let uid = user_uid(user_id);
    let parents: std::collections::HashSet<EntityUid> = role_names
        .iter()
        .filter_map(|name| {
            format!("AuthRS::Role::\"{}\"", name).parse().ok()
        })
        .collect();
    Entity::new_no_attrs(uid, parents)
}

/// Builds the full ancestor chain for a resource path.
/// "service:core/package:manufacturing_core/table:materials/column:material_name"
/// produces four Entity objects: Service, Package, Table, Column — each pointing to its parent
/// (when the schema allows that membership). Each entity's type comes from its segment prefix,
/// matching [`resource_root_uid`], and carries a `path` attribute (the prefixed path up to and
/// including that segment) that wildcard policies match with `like`.
fn build_resource_chain(resource_path: &str) -> Vec<Entity> {
    let raw_segments: Vec<&str> = resource_path.split('/').collect();

    let mut entities = Vec::new();
    let mut parent: Option<(&str, EntityUid)> = None;

    for i in 0..raw_segments.len() {
        let entity_type = resource::segment_entity_type(raw_segments[i]);
        let uid = match resource_uid(entity_type, &resource::entity_id(&raw_segments[..=i])) {
            Ok(u) => u,
            Err(_) => {
                parent = None;
                continue;
            }
        };

        let parents: HashSet<EntityUid> = parent
            .take()
            .filter(|(parent_type, _)| resource::allows_parent(entity_type, parent_type))
            .map(|(_, uid)| uid)
            .into_iter()
            .collect();

        let attrs = HashMap::from([(
            "path".to_string(),
            RestrictedExpression::new_string(raw_segments[..=i].join("/")),
        )]);
        match Entity::new(uid.clone(), attrs, parents) {
            Ok(entity) => entities.push(entity),
            Err(_) => continue,
        }
        parent = Some((entity_type, uid));
    }

    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::compiler::compile;
    use crate::policy::domain::{Effect, PermissionDocument, PermissionStatement};
    use crate::policy::schema::{build_schema_str, parse_schema};

    fn schema() -> Schema {
        let tables = vec![("orders_pkg".to_string(), "orders".to_string())];
        parse_schema(&build_schema_str(&tables, &[])).expect("schema")
    }

    fn policies(effect: Effect, actions: &[&str], resources: &[&str]) -> PolicySet {
        let doc = PermissionDocument {
            version: "1.0".into(),
            statements: vec![PermissionStatement {
                sid: "s".into(),
                effect,
                principals: vec!["*".into()],
                actions: actions.iter().map(|a| a.to_string()).collect(),
                resources: resources.iter().map(|r| r.to_string()).collect(),
                conditions: vec![],
            }],
        };
        compile(&doc, "p").expect("compile")
    }

    fn allowed(set: &PolicySet, action: &str, resource: &str) -> bool {
        let req = AuthzRequest {
            user_id: Uuid::nil(),
            role_names: &[],
            action,
            resource,
            context: serde_json::json!({}),
        };
        matches!(authorize(&req, set, &schema()), Decision::Allow)
    }

    const SAMPLE: &str = "service:core/package:_default/query:sample";

    #[test]
    fn exact_query_resource_matches_only_that_query() {
        let set = policies(Effect::Allow, &["run"], &[SAMPLE]);
        assert!(allowed(&set, "run", SAMPLE));
        assert!(!allowed(
            &set,
            "run",
            "service:core/package:_default/query:other"
        ));
    }

    #[test]
    fn query_wildcard_matches_every_query_in_the_package_only() {
        let set = policies(
            Effect::Allow,
            &["run"],
            &["service:core/package:_default/query:*"],
        );
        assert!(allowed(&set, "run", SAMPLE));
        assert!(allowed(
            &set,
            "run",
            "service:core/package:_default/query:test"
        ));
        assert!(!allowed(
            &set,
            "run",
            "service:core/package:other/query:sample"
        ));
        assert!(!allowed(
            &set,
            "run",
            "service:core/package:_default/table:orders"
        ));
        assert!(!allowed(
            &set,
            "run",
            "service:other/package:_default/query:sample"
        ));
    }

    #[test]
    fn builtin_run_applies_to_queries_only() {
        let set = policies(Effect::Allow, &["run"], &["*"]);
        assert!(allowed(&set, "run", SAMPLE));
        assert!(!allowed(&set, "run", "service:core/package:orders_pkg/table:orders"));
        assert!(!allowed(&set, "run", "service:core/package:orders_pkg"));
    }

    #[test]
    fn prefix_wildcard_covers_everything_below() {
        let set = policies(Effect::Allow, &["run", "getOrders"], &["service:core/*"]);
        assert!(allowed(&set, "run", SAMPLE));
        assert!(allowed(
            &set,
            "getOrders",
            "service:core/package:orders_pkg/table:orders"
        ));
        assert!(!allowed(
            &set,
            "getOrders",
            "service:billing/package:orders_pkg/table:orders"
        ));
    }

    #[test]
    fn star_matches_any_resource_and_action_must_still_match() {
        let set = policies(Effect::Allow, &["run"], &["*"]);
        assert!(allowed(&set, "run", SAMPLE));
        assert!(!allowed(
            &set,
            "getOrders",
            "service:core/package:orders_pkg/table:orders"
        ));
    }

    #[test]
    fn wildcard_deny_overrides_exact_allow() {
        let mut set = policies(Effect::Allow, &["run"], &[SAMPLE]);
        for p in policies(
            Effect::Deny,
            &["run"],
            &["service:core/package:_default/query:*"],
        )
        .policies()
        {
            set.add(p.clone()).unwrap();
        }
        assert!(!allowed(&set, "run", SAMPLE));
    }

    #[test]
    fn table_and_column_resources_still_match_exactly() {
        let table = "service:core/package:orders_pkg/table:orders";
        let set = policies(Effect::Allow, &["getOrders"], &[table]);
        assert!(allowed(&set, "getOrders", table));
        assert!(!allowed(
            &set,
            "getOrders",
            "service:core/package:orders_pkg/table:orders/column:total"
        ));
    }
}
