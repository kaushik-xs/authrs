//! Cedar authorization engine: builds entities and evaluates requests.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityUid, PolicySet, Request, Schema,
};
use uuid::Uuid;

use crate::policy::schema::to_pascal_case;

pub struct AuthzRequest<'a> {
    pub user_id: Uuid,
    /// Role names taken directly from the session — no DB lookup needed.
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
        Err(_) => return Decision::Deny,
    };
    let action_uid = match action_uid(req.action) {
        Ok(uid) => uid,
        Err(_) => return Decision::Deny,
    };

    let mut all_entities = build_resource_chain(req.resource);
    all_entities.push(build_user_entity(req.user_id, req.role_names));

    let entities =
        Entities::from_entities(all_entities, Some(schema)).unwrap_or_else(|_| Entities::empty());

    let ctx = Context::from_json_value(req.context.clone(), None)
        .unwrap_or_else(|_| Context::empty());

    let request = match Request::new(principal_uid, action_uid, resource_uid, ctx, Some(schema)) {
        Ok(r) => r,
        Err(_) => return Decision::Deny,
    };

    Authorizer::new()
        .is_authorized(&request, policy_set, &entities)
        .decision()
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

fn resource_root_uid(resource: &str) -> Result<EntityUid, ()> {
    let segments: Vec<&str> = resource.split('/').collect();
    let last = segments.last().copied().unwrap_or(resource);
    let entity_type = if last.starts_with("column:") {
        "Column"
    } else if last.starts_with("table:") {
        "Table"
    } else if last.starts_with("package:") {
        "Package"
    } else {
        "Service"
    };
    let id = segments
        .iter()
        .map(|s| s.splitn(2, ':').nth(1).unwrap_or(s))
        .collect::<Vec<_>>()
        .join("/");
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
/// produces four Entity objects: Service, Package, Table, Column — each pointing to its parent.
fn build_resource_chain(resource: &str) -> Vec<Entity> {
    let type_names = ["Service", "Package", "Table", "Column"];
    let raw_segments: Vec<&str> = resource.split('/').collect();
    let id_segments: Vec<&str> = raw_segments
        .iter()
        .map(|s| s.splitn(2, ':').nth(1).unwrap_or(s))
        .collect();

    let mut entities = Vec::new();

    for (i, id_seg) in id_segments.iter().enumerate() {
        let _ = id_seg; // used below via id_segments[..=i]
        let type_name = type_names.get(i).copied().unwrap_or("Service");
        let full_id = id_segments[..=i].join("/");
        let uid: EntityUid = match format!("AuthRS::{}::\"{}\"", type_name, full_id).parse() {
            Ok(u) => u,
            Err(_) => continue,
        };

        let parents: std::collections::HashSet<EntityUid> = if i > 0 {
            let parent_type = type_names[i - 1];
            let parent_id = id_segments[..i].join("/");
            format!("AuthRS::{}::\"{}\"", parent_type, parent_id)
                .parse()
                .ok()
                .into_iter()
                .collect()
        } else {
            std::collections::HashSet::new()
        };

        entities.push(Entity::new_no_attrs(uid, parents));
    }

    entities
}
