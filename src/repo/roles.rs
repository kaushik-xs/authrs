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
            FROM auth.permissions p
            INNER JOIN auth.role_permissions rp ON rp.permission_id = p.id
            INNER JOIN auth.user_roles ur ON ur.role_id = rp.role_id
            WHERE ur.user_id = $1 AND p.tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(n,)| n).collect())
    }

    /// Role names for the user (direct assignment via user_roles).
    pub async fn get_user_roles(&self, tenant_id: &str, user_id: Uuid) -> Result<Vec<String>, AppError> {
        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT r.name
            FROM auth.roles r
            INNER JOIN auth.user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.tenant_id = $2
            ORDER BY r.name
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(n,)| n).collect())
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
            INSERT INTO auth.user_roles (user_id, role_id)
            SELECT $1, $2
            WHERE EXISTS (SELECT 1 FROM auth.users u WHERE u.id = $1 AND u.tenant_id = $3)
            AND EXISTS (SELECT 1 FROM auth.roles r WHERE r.id = $2 AND r.tenant_id = $3)
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
            "DELETE FROM auth.user_roles WHERE user_id = $1 AND role_id = $2",
        )
        .bind(user_id)
        .bind(role_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// List all roles for a tenant (id, name).
    pub async fn list_roles(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<(Uuid, String)>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, name FROM auth.roles WHERE tenant_id = $1 ORDER BY name",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Get role id by tenant and role name.
    pub async fn get_role_id_by_name(
        &self,
        tenant_id: &str,
        role_name: &str,
    ) -> Result<Option<Uuid>, AppError> {
        let id = sqlx::query_scalar(
            "SELECT id FROM auth.roles WHERE tenant_id = $1 AND name = $2",
        )
        .bind(tenant_id)
        .bind(role_name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(id)
    }
}
