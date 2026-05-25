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

    /// Sync a package: upsert its tables and custom actions, rebuild Cedar schema,
    /// and evict all PolicySet caches so the next request recompiles.
    pub async fn sync(
        &self,
        package_id: &str,
        tables: &[String],
        custom_actions: &[String],
    ) -> Result<(), AppError> {
        self.repo.sync_tables(package_id, tables).await?;
        self.repo
            .sync_custom_actions(package_id, custom_actions)
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

    /// Returns all action names relevant to the given resource path.
    ///
    /// Scope is determined by the deepest segment in the path:
    /// - `service:x`                          → all actions across all packages
    /// - `service:x/package:y`                → all actions in package y
    /// - `service:x/package:y/table:z`        → CRUD + custom actions for table z
    /// - `service:x/package:y/table:z/column` → same as table level
    pub async fn get_actions_for_resource(
        &self,
        resource: &str,
    ) -> Result<Vec<String>, AppError> {
        let (package_id, table_name) = parse_resource_scope(resource);

        let all_tables = self.repo.list_tables().await?;
        let all_custom = self.repo.list_custom_actions().await?;

        let mut actions: Vec<String> = Vec::new();

        // CRUD actions derived from matching tables
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
                let pascal = crate::policy::schema::to_pascal_case(tbl);
                for verb in &["get", "post", "patch", "put", "delete"] {
                    actions.push(format!("{verb}{pascal}"));
                }
            }
        }

        // Custom actions scoped to matching packages
        for (pkg, action) in &all_custom {
            let include = match &package_id {
                Some(p) => pkg == p,
                None => true,
            };
            if include {
                actions.push(action.clone());
            }
        }

        actions.sort();
        actions.dedup();
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
