//! Roles, role_permissions, user_roles: roles are assigned only to users (never to groups).

use crate::error::AppError;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct RolesRepo {
    pool: PgPool,
}

impl RolesRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// All permission names for the user (through user_roles -> role_permissions).
    pub async fn get_user_permissions(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<String>, AppError> {
        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT DISTINCT p.name
            FROM permissions p
            INNER JOIN role_permissions rp ON rp.permission_id = p.id
            INNER JOIN user_roles ur ON ur.role_id = rp.role_id
            WHERE ur.user_id = $1 AND p.tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(n,)| n).collect())
    }

    /// Role uids for the user (direct assignment via user_roles).
    /// Used to populate the session and Cedar entities.
    pub async fn get_user_roles(&self, tenant_id: &str, user_id: Uuid) -> Result<Vec<String>, AppError> {
        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT r.uid
            FROM roles r
            INNER JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.tenant_id = $2
            ORDER BY r.uid
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(uid,)| uid).collect())
    }

    /// Full role details (id, name, uid) for a user — used by admin listing endpoints.
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
    pub async fn create(&self, tenant_id: &str, name: &str) -> Result<(Uuid, String, String), AppError> {
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
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO roles (id, tenant_id, name, uid) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(&uid)
        .execute(&self.pool)
        .await?;
        Ok((id, name.to_string(), uid))
    }

    /// List all roles for a tenant (id, name, uid).
    pub async fn list_roles(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<(Uuid, String, String)>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid, String, String)>(
            "SELECT id, name, uid FROM roles WHERE tenant_id = $1 ORDER BY name",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Role UUIDs for the user (direct assignment via user_roles).
    pub async fn get_user_role_ids(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid,)>(
            r#"
            SELECT r.id
            FROM roles r
            INNER JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.tenant_id = $2
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
        // Try exact uid match first
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT uid FROM roles WHERE tenant_id = $1 AND (uid = $2 OR name = $2)",
        )
        .bind(tenant_id)
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(uid,)| uid))
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
