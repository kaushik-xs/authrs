//! Roles, role_permissions, user_roles: roles are assigned only to users (never to groups).

use crate::error::AppError;
use crate::query::{self, FieldSpec, FieldType, FilterNode, SortSpec};
use sqlx::PgPool;
use uuid::Uuid;

/// RSQL-filterable/sortable fields for `GET /admin/roles`.
pub const ROLE_FILTER_FIELDS: &[FieldSpec] = &[
    FieldSpec { api_name: "id", column: "id", ty: FieldType::Uuid, sensitive: false },
    FieldSpec { api_name: "name", column: "name", ty: FieldType::Text, sensitive: false },
    FieldSpec { api_name: "uid", column: "uid", ty: FieldType::Text, sensitive: false },
    FieldSpec { api_name: "parentRoleId", column: "parent_role_id", ty: FieldType::Uuid, sensitive: false },
];

#[derive(Clone)]
pub struct RolesRepo {
    pool: PgPool,
}

impl RolesRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// All permission names for the user (through user_roles -> ancestor roles -> role_permissions).
    pub async fn get_user_permissions(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<String>, AppError> {
        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            WITH RECURSIVE role_ancestors AS (
                SELECT r.id, r.parent_role_id
                FROM roles r
                INNER JOIN user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = $1 AND r.tenant_id = $2
                UNION
                SELECT r.id, r.parent_role_id
                FROM roles r
                INNER JOIN role_ancestors ra ON r.id = ra.parent_role_id
                WHERE r.tenant_id = $2
            )
            SELECT DISTINCT p.name
            FROM permissions p
            INNER JOIN role_permissions rp ON rp.permission_id = p.id
            INNER JOIN role_ancestors ra ON ra.id = rp.role_id
            WHERE p.tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(n,)| n).collect())
    }

    /// Role uids for the user (direct + ancestors via hierarchy).
    /// Used to populate the session and Cedar entities.
    pub async fn get_user_roles(&self, tenant_id: &str, user_id: Uuid) -> Result<Vec<String>, AppError> {
        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            WITH RECURSIVE role_ancestors AS (
                SELECT r.id, r.uid, r.parent_role_id
                FROM roles r
                INNER JOIN user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = $1 AND r.tenant_id = $2
                UNION
                SELECT r.id, r.uid, r.parent_role_id
                FROM roles r
                INNER JOIN role_ancestors ra ON r.id = ra.parent_role_id
                WHERE r.tenant_id = $2
            )
            SELECT DISTINCT uid FROM role_ancestors ORDER BY uid
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(uid,)| uid).collect())
    }

    /// Full role details (id, name, uid) for a user — used by admin listing endpoints.
    /// Returns only directly assigned roles (not ancestors) for display purposes.
    pub async fn get_user_roles_detail(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, String, String)>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid, String, String)>(
            r#"
            SELECT r.id, r.name, r.uid
            FROM roles r
            INNER JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.tenant_id = $2
            ORDER BY r.name
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Assign a role to a user. Returns NotFound if user or role not in tenant.
    pub async fn assign_role_to_user(
        &self,
        tenant_id: &str,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<(), AppError> {
        let r = sqlx::query(
            r#"
            INSERT INTO user_roles (user_id, role_id)
            SELECT $1, $2
            WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = $1 AND u.tenant_id = $3)
            AND EXISTS (SELECT 1 FROM roles r WHERE r.id = $2 AND r.tenant_id = $3)
            "#,
        )
        .bind(user_id)
        .bind(role_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        if r.rows_affected() == 0 {
            return Err(AppError::NotFound(
                "User or role not found in tenant".to_string(),
            ));
        }
        Ok(())
    }

    /// Remove a role from a user.
    pub async fn remove_role_from_user(
        &self,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, AppError> {
        let r = sqlx::query(
            "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2",
        )
        .bind(user_id)
        .bind(role_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Create a role for a tenant. Returns Conflict if a role with the same uid already exists.
    /// Returns (id, name, uid).
    pub async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        parent_role_id: Option<Uuid>,
    ) -> Result<(Uuid, String, String), AppError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(AppError::BadRequest("Role name is required".to_string()));
        }
        let uid = to_uid(name);
        if self.get_role_id_by_uid(tenant_id, &uid).await?.is_some() {
            return Err(AppError::Conflict(format!(
                "A role with uid '{}' already exists for this tenant",
                uid
            )));
        }
        if let Some(parent_id) = parent_role_id {
            self.validate_parent(tenant_id, parent_id, None).await?;
        }
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO roles (id, tenant_id, name, uid, parent_role_id) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(&uid)
        .bind(parent_role_id)
        .execute(&self.pool)
        .await?;
        Ok((id, name.to_string(), uid))
    }

    /// Set or clear the parent of an existing role.
    /// Returns NotFound if role_id is not in the tenant.
    /// Returns BadRequest if setting the parent would create a cycle.
    pub async fn set_parent(
        &self,
        tenant_id: &str,
        role_id: Uuid,
        parent_role_id: Option<Uuid>,
    ) -> Result<(), AppError> {
        // Ensure role exists in tenant.
        let exists: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM roles WHERE id = $1 AND tenant_id = $2",
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound("Role not found in tenant".to_string()));
        }
        if let Some(parent_id) = parent_role_id {
            self.validate_parent(tenant_id, parent_id, Some(role_id)).await?;
        }
        sqlx::query(
            "UPDATE roles SET parent_role_id = $1 WHERE id = $2 AND tenant_id = $3",
        )
        .bind(parent_role_id)
        .bind(role_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete a role. Returns true if deleted.
    ///
    /// Cascades: `role_permissions`, `user_roles`, and `group_roles` rows referencing
    /// this role are removed via `ON DELETE CASCADE`; any child roles have their
    /// `parent_role_id` set to NULL via `ON DELETE SET NULL`.
    pub async fn delete(&self, tenant_id: &str, role_id: Uuid) -> Result<bool, AppError> {
        let r = sqlx::query(
            "DELETE FROM roles WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(role_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Returns the full ancestor chain for a role (excluding the role itself), root-first.
    pub async fn get_role_ancestors(
        &self,
        tenant_id: &str,
        role_id: Uuid,
    ) -> Result<Vec<(Uuid, String, String)>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid, String, String)>(
            r#"
            WITH RECURSIVE ancestors AS (
                SELECT r.id, r.name, r.uid, r.parent_role_id, 1 AS depth
                FROM roles r
                WHERE r.id = (SELECT parent_role_id FROM roles WHERE id = $1 AND tenant_id = $2)
                  AND r.tenant_id = $2
                UNION ALL
                SELECT r.id, r.name, r.uid, r.parent_role_id, a.depth + 1
                FROM roles r
                INNER JOIN ancestors a ON r.id = a.parent_role_id
                WHERE r.tenant_id = $2
            )
            SELECT id, name, uid FROM ancestors ORDER BY depth DESC
            "#,
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// List all roles for a tenant (id, name, uid, parent_role_id). Supports optional RSQL
    /// `filter`/`sort` (validated against [`ROLE_FILTER_FIELDS`]) plus `limit`/`offset`.
    /// With no `sort`, falls back to name ASC.
    pub async fn list_roles(
        &self,
        tenant_id: &str,
        filter: Option<&FilterNode>,
        sort: &[SortSpec],
        limit: u32,
        offset: u32,
    ) -> Result<Vec<(Uuid, String, String, Option<Uuid>)>, AppError> {
        let built = query::build(filter, sort, ROLE_FILTER_FIELDS, 2)?;
        let mut where_sql = String::from("tenant_id = $1");
        if !built.where_sql.is_empty() {
            where_sql.push_str(" AND ");
            where_sql.push_str(&built.where_sql);
        }
        let order_sql = if built.order_sql.is_empty() {
            " ORDER BY name".to_string()
        } else {
            built.order_sql
        };
        let sql = format!(
            "SELECT id, name, uid, parent_role_id FROM roles WHERE {where_sql}{order_sql} LIMIT {limit} OFFSET {offset}"
        );
        let mut q = sqlx::query_as::<_, (Uuid, String, String, Option<Uuid>)>(&sql).bind(tenant_id);
        for p in &built.params {
            q = q.bind(p);
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows)
    }

    /// Role UUIDs for the user (direct + ancestors via hierarchy) — for policy set loading.
    pub async fn get_user_role_ids(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid,)>(
            r#"
            WITH RECURSIVE role_ancestors AS (
                SELECT r.id, r.parent_role_id
                FROM roles r
                INNER JOIN user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = $1 AND r.tenant_id = $2
                UNION
                SELECT r.id, r.parent_role_id
                FROM roles r
                INNER JOIN role_ancestors ra ON r.id = ra.parent_role_id
                WHERE r.tenant_id = $2
            )
            SELECT DISTINCT id FROM role_ancestors
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Get role id by tenant and role name.
    pub async fn get_role_id_by_name(
        &self,
        tenant_id: &str,
        role_name: &str,
    ) -> Result<Option<Uuid>, AppError> {
        let id = sqlx::query_scalar(
            "SELECT id FROM roles WHERE tenant_id = $1 AND name = $2",
        )
        .bind(tenant_id)
        .bind(role_name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(id)
    }

    /// Get role id by tenant and uid.
    pub async fn get_role_id_by_uid(
        &self,
        tenant_id: &str,
        uid: &str,
    ) -> Result<Option<Uuid>, AppError> {
        let id = sqlx::query_scalar(
            "SELECT id FROM roles WHERE tenant_id = $1 AND uid = $2",
        )
        .bind(tenant_id)
        .bind(uid)
        .fetch_optional(&self.pool)
        .await?;
        Ok(id)
    }

    /// Resolve a role identifier (name or uid) to its uid for use in permission principals.
    /// Returns None if no matching role is found.
    pub async fn resolve_role_uid(
        &self,
        tenant_id: &str,
        identifier: &str,
    ) -> Result<Option<String>, AppError> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT uid FROM roles WHERE tenant_id = $1 AND (uid = $2 OR name = $2)",
        )
        .bind(tenant_id)
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(uid,)| uid))
    }

    /// Validate that parent_role_id belongs to the tenant and that setting it as the parent
    /// of `child_role_id` (if given) would not create a cycle.
    async fn validate_parent(
        &self,
        tenant_id: &str,
        parent_role_id: Uuid,
        child_role_id: Option<Uuid>,
    ) -> Result<(), AppError> {
        // Parent must belong to the same tenant.
        let exists: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM roles WHERE id = $1 AND tenant_id = $2",
        )
        .bind(parent_role_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound(
                "Parent role not found in tenant".to_string(),
            ));
        }
        // Cycle check: walk up from the proposed parent; if we reach child_role_id, it's a cycle.
        if let Some(child_id) = child_role_id {
            if parent_role_id == child_id {
                return Err(AppError::BadRequest(
                    "A role cannot be its own parent".to_string(),
                ));
            }
            // Walk the ancestor chain of parent_role_id; if child_id appears, reject.
            let cycle: Option<Uuid> = sqlx::query_scalar(
                r#"
                WITH RECURSIVE ancestors AS (
                    SELECT id, parent_role_id FROM roles WHERE id = $1
                    UNION ALL
                    SELECT r.id, r.parent_role_id
                    FROM roles r
                    INNER JOIN ancestors a ON r.id = a.parent_role_id
                    WHERE r.tenant_id = $3
                )
                SELECT id FROM ancestors WHERE id = $2 LIMIT 1
                "#,
            )
            .bind(parent_role_id)
            .bind(child_id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await?;
            if cycle.is_some() {
                return Err(AppError::BadRequest(
                    "Setting this parent would create a role hierarchy cycle".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Convert a role name to a stable uid slug:
/// lowercase, non-alphanumeric runs become '_', leading/trailing '_' stripped.
/// "Admin User" → "admin_user", "Super  Admin!" → "super_admin"
pub fn to_uid(name: &str) -> String {
    let lower = name.trim().to_lowercase();
    let mut uid = String::with_capacity(lower.len());
    let mut prev_underscore = true; // suppress leading underscores
    for c in lower.chars() {
        if c.is_alphanumeric() {
            uid.push(c);
            prev_underscore = false;
        } else if !prev_underscore {
            uid.push('_');
            prev_underscore = true;
        }
    }
    // Strip trailing underscore
    if uid.ends_with('_') {
        uid.pop();
    }
    uid
}
