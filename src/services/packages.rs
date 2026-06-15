//! PackagesService: syncs package/table/action registry and rebuilds the Cedar schema.

use cedar_policy::Schema;
use std::sync::{Arc, RwLock};

use crate::error::AppError;
use crate::policy::schema::{build_schema_str, parse_schema};
use crate::repo::packages::PackagesRepo;
use crate::services::permissions::PermissionsService;

#[derive(Clone)]
pub struct PackagesService {
    repo: PackagesRepo,
    cedar_schema: Arc<RwLock<Schema>>,
    permissions_service: PermissionsService,
}

impl PackagesService {
    pub fn new(
        repo: PackagesRepo,
        cedar_schema: Arc<RwLock<Schema>>,
        permissions_service: PermissionsService,
    ) -> Self {
        Self {
            repo,
            cedar_schema,
            permissions_service,
        }
    }

    /// Sync a package: delete all existing package_id data, then reinsert tables and all actions
    /// (CRUD + custom) atomically, rebuild Cedar schema, and evict all PolicySet caches.
    ///
    /// Standard actions (get/post/patch/put/delete/archive/unarchive{Table}) are derived from the
    /// table list and stored alongside any explicit custom actions so _auth_package_actions is a complete registry.
    pub async fn sync(
        &self,
        package_id: &str,
        tables: &[String],
        extensible_tables: &[String],
        custom_actions: &[String],
    ) -> Result<(), AppError> {
        // Derive CRUD actions from the table list (mirrors build_schema_str logic)
        let mut all_actions: Vec<String> = tables
            .iter()
            .flat_map(|table| crate::policy::schema::crud_action_names(table))
            .collect();
        // Derive extensible-fields actions for the tables flagged extensible
        all_actions.extend(
            extensible_tables
                .iter()
                .flat_map(|table| crate::policy::schema::extensible_action_names(table)),
        );
        all_actions.extend_from_slice(custom_actions);
        all_actions.sort();
        all_actions.dedup();

        self.repo
            .sync_package(package_id, tables, &all_actions)
            .await?;

        self.rebuild_schema().await?;
        self.permissions_service.evict_all();
        Ok(())
    }

    /// Reload the Cedar schema from the full _auth_packages / _auth_package_actions tables.
    pub async fn rebuild_schema(&self) -> Result<(), AppError> {
        let package_tables = self.repo.list_tables().await?;
        let custom_actions = self.repo.list_custom_actions().await?;
        let schema_str = build_schema_str(&package_tables, &custom_actions);
        let schema = parse_schema(&schema_str)
            .map_err(|e| AppError::Internal(format!("Cedar schema error: {e}")))?;
        *self.cedar_schema.write().unwrap() = schema;
        Ok(())
    }

    pub fn cedar_schema(&self) -> Arc<RwLock<Schema>> {
        Arc::clone(&self.cedar_schema)
    }

    /// Returns all (package_id, action_name) pairs from _auth_package_actions.
    pub async fn list_all_actions(&self) -> Result<Vec<(String, String)>, AppError> {
        self.repo.list_custom_actions().await
    }

    /// Returns all (package_id, table_name) pairs from _auth_packages.
    pub async fn list_all_tables(&self) -> Result<Vec<(String, String)>, AppError> {
        self.repo.list_tables().await
    }

    /// Returns `(action_name, specific_resource)` pairs relevant to the given resource path.
    ///
    /// `specific_resource` is the most precise resource path for that action so Cedar's
    /// `resource ==` check in the compiled policy matches correctly. For CRUD actions this
    /// is always the table-level path; for custom actions it is the package-level path.
    ///
    /// Scope is determined by the deepest segment in the path:
    /// - `service:x`                          → all actions across all packages
    /// - `service:x/package:y`                → all actions in package y
    /// - `service:x/package:y/table:z`        → CRUD + custom actions for table z
    /// - `service:x/package:y/table:z/column` → same as table level
    pub async fn get_actions_for_resource(
        &self,
        resource: &str,
    ) -> Result<Vec<(String, String)>, AppError> {
        let (package_id, table_name) = parse_resource_scope(resource);

        // Preserve the service prefix (e.g. "service:core") so we can build full resource paths.
        let service_prefix = resource
            .split('/')
            .find(|s| s.starts_with("service:"))
            .unwrap_or("")
            .to_string();

        let all_tables = self.repo.list_tables().await?;
        let all_custom = self.repo.list_custom_actions().await?;

        // Stored (package_id, action_name) pairs — the action registry. A table is
        // "extensible" iff its extensible-fields actions were registered here during sync,
        // so no separate flag/column is needed to recover scope.
        let stored: std::collections::HashSet<(&str, &str)> = all_custom
            .iter()
            .map(|(p, a)| (p.as_str(), a.as_str()))
            .collect();

        let mut actions: Vec<(String, String)> = Vec::new();

        // CRUD + extensible-fields actions derived from matching tables.
        // Both are table-scoped: the architect-sdk proxy checks them against the
        // table-level resource, so the compiled policy's `resource ==` check must match that.
        for (pkg, tbl) in &all_tables {
            let include = match (&package_id, &table_name) {
                // table or column scope: exact table match within the package
                (Some(p), Some(t)) => pkg == p && tbl == t,
                // package scope: all tables in the package
                (Some(p), None) => pkg == p,
                // service scope: all tables
                (None, _) => true,
            };
            if include {
                // Policies are compiled with resource == <table-level path>; use that exact
                // path so the Cedar equality check fires rather than comparing against a
                // higher-level Package or Service entity.
                let table_resource = if service_prefix.is_empty() {
                    format!("package:{pkg}/table:{tbl}")
                } else {
                    format!("{service_prefix}/package:{pkg}/table:{tbl}")
                };
                for action in crate::policy::schema::crud_action_names(tbl) {
                    actions.push((action, table_resource.clone()));
                }
                // Extensible iff the derived extensible actions are in the registry.
                let ext_actions = crate::policy::schema::extensible_action_names(tbl);
                let is_extensible = ext_actions
                    .iter()
                    .any(|a| stored.contains(&(pkg.as_str(), a.as_str())));
                if is_extensible {
                    for action in ext_actions {
                        actions.push((action, table_resource.clone()));
                    }
                }
            }
        }

        // Custom actions are stored at package scope.
        for (pkg, action) in &all_custom {
            let include = match &package_id {
                Some(p) => pkg == p,
                None => true,
            };
            if include {
                let pkg_resource = if service_prefix.is_empty() {
                    format!("package:{pkg}")
                } else {
                    format!("{service_prefix}/package:{pkg}")
                };
                actions.push((action.clone(), pkg_resource));
            }
        }

        actions.sort_by(|a, b| a.0.cmp(&b.0));
        actions.dedup_by(|a, b| a.0 == b.0);
        Ok(actions)
    }
}

/// Extracts (package_id, table_name) from a resource path.
/// Returns None for levels not present in the path.
fn parse_resource_scope(resource: &str) -> (Option<String>, Option<String>) {
    let mut package_id = None;
    let mut table_name = None;
    for segment in resource.split('/') {
        if let Some(p) = segment.strip_prefix("package:") {
            package_id = Some(p.to_string());
        } else if let Some(t) = segment.strip_prefix("table:") {
            table_name = Some(t.to_string());
        }
    }
    (package_id, table_name)
}
