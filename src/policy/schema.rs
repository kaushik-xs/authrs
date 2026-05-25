//! Builds the Cedar schema string dynamically from registered packages and tables.

use cedar_policy::{CedarSchemaError, Schema};

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

/// Builds the full Cedar schema string from the registered (package_id, table_name) pairs
/// and custom per-package actions.
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
        let pascal = to_pascal_case(table_name);
        for verb in &["get", "post", "patch", "put", "delete"] {
            action_lines.push(format!(
                r#"  action "{verb}{pascal}" {applies_to};"#
            ));
        }
    }

    // Custom actions per package
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
