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
}
