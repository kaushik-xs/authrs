//! Resource path helpers shared by the policy compiler and the authorization engine, so the
//! entity types/ids a policy names always agree with the ones a request builds.
//!
//! A resource path is a `/`-separated list of `prefix:id` segments, e.g.
//! "service:core/package:manufacturing_core/table:materials". The entity type comes from the
//! prefix of the last segment and the entity id is the path with the prefixes stripped.
//!
//! A resource containing `*` is a wildcard pattern matched against the full path, e.g.
//! "service:core/package:_default/query:*" or "service:core/*". `*` matches any run of
//! characters, including `/`, so "table:*" also covers columns under those tables.

use serde_json::{json, Value};

/// Cedar entity type (without namespace) for one path segment. Unknown prefixes map to Service.
pub fn segment_entity_type(segment: &str) -> &'static str {
    match segment.split_once(':').map(|(prefix, _)| prefix) {
        Some("package") => "Package",
        Some("table") => "Table",
        Some("column") => "Column",
        Some("query") => "Query",
        _ => "Service",
    }
}

/// Whether the schema lets an entity of type `child` be a member of an entity of type `parent`.
pub fn allows_parent(child: &str, parent: &str) -> bool {
    matches!(
        (child, parent),
        ("Package", "Service") | ("Table", "Package") | ("Column", "Table") | ("Query", "Package")
    )
}

/// Cedar entity type (without namespace) for a full resource path.
pub fn entity_type(resource: &str) -> &'static str {
    segment_entity_type(resource.rsplit('/').next().unwrap_or(resource))
}

/// Canonical entity id for a resource path: the segments with their prefixes stripped.
pub fn entity_id(segments: &[&str]) -> String {
    segments
        .iter()
        .map(|s| s.split_once(':').map(|(_, id)| id).unwrap_or(s))
        .collect::<Vec<_>>()
        .join("/")
}

pub fn is_wildcard(resource: &str) -> bool {
    resource.contains('*')
}

/// Cedar JSON (EST) `like` pattern for a wildcard resource: each `*` becomes a Wildcard element
/// and the text between them a Literal.
pub fn like_pattern(resource: &str) -> Vec<Value> {
    let mut elems = Vec::new();
    for (i, literal) in resource.split('*').enumerate() {
        if i > 0 {
            elems.push(json!("Wildcard"));
        }
        if !literal.is_empty() {
            elems.push(json!({ "Literal": literal }));
        }
    }
    elems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_type_follows_last_segment_prefix() {
        assert_eq!(entity_type("service:core"), "Service");
        assert_eq!(entity_type("service:core/package:p"), "Package");
        assert_eq!(entity_type("service:core/package:p/table:t"), "Table");
        assert_eq!(
            entity_type("service:core/package:p/table:t/column:c"),
            "Column"
        );
        assert_eq!(
            entity_type("service:core/package:_default/query:q"),
            "Query"
        );
        assert_eq!(entity_type("service:core/package:p/report:r"), "Service");
    }

    #[test]
    fn entity_id_strips_prefixes() {
        let segs: Vec<&str> = "service:core/package:_default/query:sample"
            .split('/')
            .collect();
        assert_eq!(entity_id(&segs), "core/_default/sample");
    }

    #[test]
    fn like_pattern_splits_on_stars() {
        assert_eq!(
            like_pattern("service:core/package:_default/query:*"),
            vec![
                json!({ "Literal": "service:core/package:_default/query:" }),
                json!("Wildcard")
            ]
        );
        assert_eq!(
            like_pattern("service:*/table:*s"),
            vec![
                json!({ "Literal": "service:" }),
                json!("Wildcard"),
                json!({ "Literal": "/table:" }),
                json!("Wildcard"),
                json!({ "Literal": "s" }),
            ]
        );
        assert_eq!(like_pattern("*"), vec![json!("Wildcard")]);
    }
}
