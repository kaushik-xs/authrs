//! Builds the Cedar schema string dynamically from registered packages and tables.

use cedar_policy::{CedarSchemaError, Schema};

/// Standard CRUD verbs derived for every registered table.
pub const CRUD_VERBS: [&str; 7] =
    ["get", "post", "patch", "put", "delete", "archive", "unarchive"];

/// Compound verbs derived for every table flagged `extensible`. These mirror the
/// extensible-fields routes the architect-sdk proxy serves and the action names it
/// derives at request time (`<verb> + PascalCase(table)`):
///   GET  /extensible-fields and GET  /extensible-fields/indexes -> getExtensibleFields<Table>
///   PUT  /extensible-fields and POST /extensible-fields/indexes -> putExtensibleFields<Table>
///   DELETE /extensible-fields                                   -> deleteExtensibleFields<Table>
pub const EXTENSIBLE_VERBS: [&str; 3] =
    ["getExtensibleFields", "putExtensibleFields", "deleteExtensibleFields"];

/// Converts a snake_case table name to PascalCase for action names.
/// e.g. "bom_materials" -> "BomMaterials", "materials" -> "Materials"
pub fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut c = part.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect()
}

/// CRUD action names for a table, e.g. "materials" -> ["getMaterials", ...].
pub fn crud_action_names(table: &str) -> Vec<String> {
    let pascal = to_pascal_case(table);
    CRUD_VERBS.iter().map(|v| format!("{v}{pascal}")).collect()
}

/// Extensible-fields action names for a table, e.g.
/// "contacts" -> ["getExtensibleFieldsContacts", "putExtensibleFieldsContacts", "deleteExtensibleFieldsContacts"].
pub fn extensible_action_names(table: &str) -> Vec<String> {
    let pascal = to_pascal_case(table);
    EXTENSIBLE_VERBS
        .iter()
        .map(|v| format!("{v}{pascal}"))
        .collect()
}

/// Builds the full Cedar schema string from the registered (package_id, table_name) pairs
/// and per-package actions (custom + the derived CRUD/extensible actions stored in
/// `_auth_package_actions`).
pub fn build_schema_str(
    package_tables: &[(String, String)],
    custom_actions: &[(String, String)],
) -> String {
    let resource_types = "[Service, Package, Table, Column]";
    let applies_to = format!(
        "appliesTo {{ principal: [User], resource: {resource_types} }}"
    );

    let mut action_lines: Vec<String> = Vec::new();

    // Auto-generated CRUD actions for every registered table
    for (_, table_name) in package_tables {
        for action_name in crud_action_names(table_name) {
            action_lines.push(format!(r#"  action "{action_name}" {applies_to};"#));
        }
    }

    // Per-package actions: genuine custom actions plus the derived extensible-fields
    // actions, which are persisted in `_auth_package_actions` during sync.
    for (_, action_name) in custom_actions {
        action_lines.push(format!(
            r#"  action "{action_name}" {applies_to};"#
        ));
    }

    // Deduplicate (two packages could share a table name)
    action_lines.sort();
    action_lines.dedup();

    format!(
        r#"namespace AuthRS {{
  entity User in [Role];
  entity Role;
  entity Service;
  entity Package in [Service];
  entity Table in [Package];
  entity Column in [Table];
{actions}
}}"#,
        actions = action_lines.join("\n")
    )
}

pub fn parse_schema(schema_str: &str) -> Result<Schema, CedarSchemaError> {
    Schema::from_cedarschema_str(schema_str).map(|(s, _warns)| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensible_action_names_match_proxy_scheme() {
        // Must match architect-sdk's runtime action derivation: <verb> + PascalCase(table).
        assert_eq!(
            extensible_action_names("contacts"),
            vec![
                "getExtensibleFieldsContacts",
                "putExtensibleFieldsContacts",
                "deleteExtensibleFieldsContacts",
            ]
        );
        // Multi-word table names use PascalCase per word.
        assert_eq!(
            extensible_action_names("bom_materials")[0],
            "getExtensibleFieldsBomMaterials"
        );
    }

    #[test]
    fn schema_declares_crud_for_tables_and_stored_extensible_actions() {
        let tables = vec![
            ("contact_management".to_string(), "contacts".to_string()),
            ("contact_management".to_string(), "notes".to_string()),
        ];
        // Extensible actions reach the schema as persisted per-package actions
        // (stored in `_auth_package_actions` during sync), not via a separate flag.
        let stored_actions: Vec<(String, String)> = extensible_action_names("contacts")
            .into_iter()
            .map(|a| ("contact_management".to_string(), a))
            .collect();
        let schema = build_schema_str(&tables, &stored_actions);

        // Extensible actions for the extensible table are declared, schema is valid Cedar.
        assert!(schema.contains(r#"action "getExtensibleFieldsContacts""#));
        assert!(schema.contains(r#"action "deleteExtensibleFieldsContacts""#));
        // No extensible actions were stored for `notes`, so none are declared.
        assert!(!schema.contains("ExtensibleFieldsNotes"));
        // CRUD still derived for every table.
        assert!(schema.contains(r#"action "getContacts""#));
        assert!(schema.contains(r#"action "getNotes""#));
        parse_schema(&schema).expect("schema must parse");
    }
}
