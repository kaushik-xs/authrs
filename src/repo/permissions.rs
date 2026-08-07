//! Permissions repository: Cedar policy documents stored as JSONB.

use crate::error::AppError;
use crate::policy::domain::PermissionDocument;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct PermissionsRepo {
    pool: PgPool,
}

impl PermissionsRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
        document: &PermissionDocument,
    ) -> Result<Uuid, AppError> {
        let id = Uuid::new_v4();
        let doc_json =
            serde_json::to_value(document).map_err(|e| AppError::Internal(e.to_string()))?;
        sqlx::query(
            r#"
            INSERT INTO permissions (id, tenant_id, name, description, document)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(description)
        .bind(doc_json)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Create a permission, or overwrite the existing one when a permission with the
    /// same (tenant_id, name) already exists. On conflict the existing row is kept —
    /// preserving its id and any role attachments — and only its description and
    /// document are updated. Returns the id of the created-or-updated row.
    pub async fn upsert(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
        document: &PermissionDocument,
    ) -> Result<Uuid, AppError> {
        let id = Uuid::new_v4();
        let doc_json =
            serde_json::to_value(document).map_err(|e| AppError::Internal(e.to_string()))?;
        let (existing_id,): (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO permissions (id, tenant_id, name, description, document)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, name)
            DO UPDATE SET description = EXCLUDED.description, document = EXCLUDED.document
            RETURNING id
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(description)
        .bind(doc_json)
        .fetch_one(&self.pool)
        .await?;
        Ok(existing_id)
    }

    pub async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<(Uuid, String, Option<String>, PermissionDocument)>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, serde_json::Value)>(
            r#"
            SELECT id, name, description, document
            FROM permissions
            WHERE tenant_id = $1 AND document IS NOT NULL
            ORDER BY name
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(id, name, desc, doc_val)| {
                let doc = serde_json::from_value::<PermissionDocument>(doc_val)
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                Ok((id, name, desc, doc))
            })
            .collect()
    }

    pub async fn get(
        &self,
        tenant_id: &str,
        permission_id: Uuid,
    ) -> Result<Option<(String, Option<String>, PermissionDocument)>, AppError> {
        let row = sqlx::query_as::<_, (String, Option<String>, serde_json::Value)>(
            r#"
            SELECT name, description, document
            FROM permissions
            WHERE id = $1 AND tenant_id = $2 AND document IS NOT NULL
            "#,
        )
        .bind(permission_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            None => Ok(None),
            Some((name, desc, doc_val)) => {
                let doc = serde_json::from_value::<PermissionDocument>(doc_val)
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                Ok(Some((name, desc, doc)))
            }
        }
    }

    pub async fn delete(&self, tenant_id: &str, permission_id: Uuid) -> Result<bool, AppError> {
        let r = sqlx::query(
            "DELETE FROM permissions WHERE id = $1 AND tenant_id = $2",
        )
        .bind(permission_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn attach_to_role(
        &self,
        tenant_id: &str,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> Result<(), AppError> {
        // Ensure both role and permission belong to the tenant
        let role_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        if !role_exists {
            return Err(AppError::NotFound("Role not found in tenant".to_string()));
        }

        let perm_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM permissions WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(permission_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        if !perm_exists {
            return Err(AppError::NotFound(
                "Permission not found in tenant".to_string(),
            ));
        }

        sqlx::query(
            "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(role_id)
        .bind(permission_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn detach_from_role(
        &self,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> Result<bool, AppError> {
        let r = sqlx::query(
            "DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2",
        )
        .bind(role_id)
        .bind(permission_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn list_for_role(
        &self,
        tenant_id: &str,
        role_id: Uuid,
    ) -> Result<Vec<(Uuid, String, PermissionDocument)>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid, String, serde_json::Value)>(
            r#"
            SELECT p.id, p.name, p.document
            FROM permissions p
            INNER JOIN role_permissions rp ON rp.permission_id = p.id
            WHERE rp.role_id = $1 AND p.tenant_id = $2 AND p.document IS NOT NULL
            ORDER BY p.name
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(id, name, doc_val)| {
                let doc = serde_json::from_value::<PermissionDocument>(doc_val)
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                Ok((id, name, doc))
            })
            .collect()
    }

    /// Fetch all distinct permission documents for a set of role IDs (used by the policy cache).
    pub async fn get_for_roles(
        &self,
        tenant_id: &str,
        role_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, PermissionDocument)>, AppError> {
        if role_ids.is_empty() {
            return Ok(vec![]);
        }
        let rows = sqlx::query_as::<_, (Uuid, serde_json::Value)>(
            r#"
            SELECT DISTINCT p.id, p.document
            FROM permissions p
            INNER JOIN role_permissions rp ON rp.permission_id = p.id
            WHERE rp.role_id = ANY($1) AND p.tenant_id = $2 AND p.document IS NOT NULL
            "#,
        )
        .bind(role_ids)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(id, doc_val)| {
                let doc = serde_json::from_value::<PermissionDocument>(doc_val)
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                Ok((id, doc))
            })
            .collect()
    }

    /// All permission documents for a tenant (used to build the full PolicySet cache).
    pub async fn list_all_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<(Uuid, PermissionDocument)>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid, serde_json::Value)>(
            r#"
            SELECT id, document FROM permissions
            WHERE tenant_id = $1 AND document IS NOT NULL
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(id, doc_val)| {
                let doc = serde_json::from_value::<PermissionDocument>(doc_val)
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                Ok((id, doc))
            })
            .collect()
    }

    /// Resolve a role name or uid to the role's uid within a tenant.
    pub async fn resolve_role_uid(
        &self,
        tenant_id: &str,
        identifier: &str,
    ) -> Result<Option<String>, AppError> {
        let uid = sqlx::query_scalar(
            "SELECT uid FROM roles WHERE tenant_id = $1 AND (uid = $2 OR name = $2)",
        )
        .bind(tenant_id)
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?;
        Ok(uid)
    }

    /// Resolve a user identifier (email or username) to their UUID within a tenant.
    pub async fn resolve_user_id(
        &self,
        tenant_id: &str,
        identifier: &str,
    ) -> Result<Option<Uuid>, AppError> {
        let id = sqlx::query_scalar(
            r#"
            SELECT id FROM users
            WHERE tenant_id = $1 AND (email = $2 OR username = $2)
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?;
        Ok(id)
    }
}
