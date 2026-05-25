//! PermissionsService: principal resolution, PolicySet cache, and eviction.

use cedar_policy::{PolicySet, Schema};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::error::AppError;
use crate::policy::compiler::compile;
use crate::policy::domain::PermissionDocument;
use crate::repo::permissions::PermissionsRepo;

#[derive(Clone)]
pub struct PermissionsService {
    repo: PermissionsRepo,
    cache: Arc<RwLock<HashMap<String, Arc<PolicySet>>>>,
}

impl PermissionsService {
    pub fn new(repo: PermissionsRepo) -> Self {
        Self {
            repo,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the compiled PolicySet for a tenant, loading from DB on cache miss.
    pub async fn get_policy_set(
        &self,
        tenant_id: &str,
        schema: &Schema,
    ) -> Result<Arc<PolicySet>, AppError> {
        // Fast path: read-lock cache hit
        {
            let guard = self.cache.read().unwrap();
            if let Some(ps) = guard.get(tenant_id) {
                return Ok(Arc::clone(ps));
            }
        }

        // Slow path: load all permissions for this tenant and compile
        let docs = self.repo.list_all_for_tenant(tenant_id).await?;
        let mut set = PolicySet::new();

        for (id, doc) in docs {
            let compiled = compile(&doc, &id.to_string())?;
            for policy in compiled.policies() {
                set.add(policy.clone())
                    .map_err(|e| AppError::Internal(e.to_string()))?;
            }
        }

        let _ = schema; // schema used for request validation in engine, not here
        let ps = Arc::new(set);
        self.cache
            .write()
            .unwrap()
            .insert(tenant_id.to_string(), Arc::clone(&ps));
        Ok(ps)
    }

    /// Evict the cached PolicySet for a tenant. Call after any permission mutation.
    pub fn evict(&self, tenant_id: &str) {
        self.cache.write().unwrap().remove(tenant_id);
    }

    /// Evict all cached PolicySets. Call after a schema rebuild (package sync).
    pub fn evict_all(&self) {
        self.cache.write().unwrap().clear();
    }

    /// Resolve human-readable principal identifiers to UUID form.
    /// "role:<name>" → "role:<uuid>", "user:<email/username>" → "user:<uuid>"
    /// Already-UUID values and "*" pass through unchanged.
    pub async fn resolve_principals(
        &self,
        tenant_id: &str,
        doc: &PermissionDocument,
    ) -> Result<PermissionDocument, AppError> {
        let mut resolved = doc.clone();
        for stmt in &mut resolved.statements {
            let mut resolved_principals = Vec::with_capacity(stmt.principals.len());
            for principal in &stmt.principals {
                let resolved_p = self.resolve_one_principal(tenant_id, principal).await?;
                resolved_principals.push(resolved_p);
            }
            stmt.principals = resolved_principals;
        }
        Ok(resolved)
    }

    async fn resolve_one_principal(
        &self,
        tenant_id: &str,
        principal: &str,
    ) -> Result<String, AppError> {
        if principal == "*" {
            return Ok(principal.to_string());
        }

        let (prefix, value) = principal
            .split_once(':')
            .ok_or_else(|| AppError::BadRequest(format!("Invalid principal format: {principal}")))?;

        // Already a UUID — pass through
        if Uuid::parse_str(value).is_ok() {
            return Ok(principal.to_string());
        }

        match prefix {
            "role" => {
                let uuid = self
                    .repo
                    .resolve_role_id(tenant_id, value)
                    .await?
                    .ok_or_else(|| {
                        AppError::BadRequest(format!("Role not found: {value}"))
                    })?;
                Ok(format!("role:{uuid}"))
            }
            "user" => {
                let uuid = self
                    .repo
                    .resolve_user_id(tenant_id, value)
                    .await?
                    .ok_or_else(|| {
                        AppError::BadRequest(format!("User not found: {value}"))
                    })?;
                Ok(format!("user:{uuid}"))
            }
            other => Err(AppError::BadRequest(format!(
                "Unknown principal prefix: {other}"
            ))),
        }
    }

    pub fn repo(&self) -> &PermissionsRepo {
        &self.repo
    }
}
