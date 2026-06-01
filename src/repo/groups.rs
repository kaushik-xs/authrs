//! Groups, user_groups, group_roles repos.

use crate::error::AppError;
use crate::repo::roles::to_uid;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct GroupsRepo {
    pool: PgPool,
}

impl GroupsRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ── Group CRUD ────────────────────────────────────────────────────────────

    /// Create a group. Returns (id, name, uid).
    pub async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<(Uuid, String, String), AppError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(AppError::BadRequest("Group name is required".to_string()));
        }
        let uid = to_uid(name);
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM groups WHERE tenant_id = $1 AND uid = $2",
        )
        .bind(tenant_id)
        .bind(&uid)
        .fetch_optional(&self.pool)
        .await?;
        if existing.is_some() {
            return Err(AppError::Conflict(format!(
                "A group with uid '{}' already exists for this tenant",
                uid
            )));
        }
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO groups (id, tenant_id, name, uid, description) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(&uid)
        .bind(description)
        .execute(&self.pool)
        .await?;
        Ok((id, name.to_string(), uid))
    }

    /// List all groups for a tenant. Returns (id, name, uid, description).
    pub async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<(Uuid, String, String, Option<String>)>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid, String, String, Option<String>)>(
            "SELECT id, name, uid, description FROM groups WHERE tenant_id = $1 ORDER BY name",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Get a single group by id. Returns (name, uid, description).
    pub async fn get(
        &self,
        tenant_id: &str,
        group_id: Uuid,
    ) -> Result<Option<(String, String, Option<String>)>, AppError> {
        let row = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT name, uid, description FROM groups WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Delete a group. Returns true if deleted.
    pub async fn delete(&self, tenant_id: &str, group_id: Uuid) -> Result<bool, AppError> {
        let r = sqlx::query(
            "DELETE FROM groups WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(group_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    // ── User membership ───────────────────────────────────────────────────────

    /// Add a user to a group. Both must belong to the tenant.
    pub async fn add_user(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        let r = sqlx::query(
            r#"
            INSERT INTO user_groups (user_id, group_id)
            SELECT $1, $2
            WHERE EXISTS (SELECT 1 FROM users  WHERE id = $1 AND tenant_id = $3)
              AND EXISTS (SELECT 1 FROM groups WHERE id = $2 AND tenant_id = $3)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(group_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        if r.rows_affected() == 0 {
            // Could be conflict (already member) or missing user/group.
            // Check which case it is.
            let group_exists: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM groups WHERE id = $1 AND tenant_id = $2",
            )
            .bind(group_id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await?;
            if group_exists.is_none() {
                return Err(AppError::NotFound("Group not found in tenant".to_string()));
            }
            // Already a member — treat as success.
        }
        Ok(())
    }

    /// Remove a user from a group. Returns true if removed.
    pub async fn remove_user(&self, group_id: Uuid, user_id: Uuid) -> Result<bool, AppError> {
        let r = sqlx::query(
            "DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2",
        )
        .bind(user_id)
        .bind(group_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// List all user IDs that are members of a group.
    pub async fn list_members(
        &self,
        tenant_id: &str,
        group_id: Uuid,
    ) -> Result<Vec<Uuid>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid,)>(
            r#"
            SELECT ug.user_id
            FROM user_groups ug
            INNER JOIN groups g ON g.id = ug.group_id
            WHERE ug.group_id = $1 AND g.tenant_id = $2
            ORDER BY ug.created_at
            "#,
        )
        .bind(group_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Groups a user belongs to. Returns (id, name, uid).
    pub async fn get_user_groups(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, String, String)>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid, String, String)>(
            r#"
            SELECT g.id, g.name, g.uid
            FROM groups g
            INNER JOIN user_groups ug ON ug.group_id = g.id
            WHERE ug.user_id = $1 AND g.tenant_id = $2
            ORDER BY g.name
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Group UIDs for a user — used for Cedar entity hierarchy.
    pub async fn get_user_group_uids(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<String>, AppError> {
        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT g.uid
            FROM groups g
            INNER JOIN user_groups ug ON ug.group_id = g.id
            WHERE ug.user_id = $1 AND g.tenant_id = $2
            ORDER BY g.uid
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(uid,)| uid).collect())
    }

    /// Group primary-key UUIDs for a user — used for policy loading.
    pub async fn get_user_group_ids(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid,)>(
            r#"
            SELECT g.id
            FROM groups g
            INNER JOIN user_groups ug ON ug.group_id = g.id
            WHERE ug.user_id = $1 AND g.tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    // ── Role assignment to groups ─────────────────────────────────────────────

    /// Assign a role to a group. Both must belong to the tenant.
    pub async fn assign_role(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<(), AppError> {
        let r = sqlx::query(
            r#"
            INSERT INTO group_roles (group_id, role_id)
            SELECT $1, $2
            WHERE EXISTS (SELECT 1 FROM groups WHERE id = $1 AND tenant_id = $3)
              AND EXISTS (SELECT 1 FROM roles  WHERE id = $2 AND tenant_id = $3)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(group_id)
        .bind(role_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        if r.rows_affected() == 0 {
            let group_exists: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM groups WHERE id = $1 AND tenant_id = $2",
            )
            .bind(group_id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await?;
            if group_exists.is_none() {
                return Err(AppError::NotFound(
                    "Group or role not found in tenant".to_string(),
                ));
            }
            // Already assigned — treat as success.
        }
        Ok(())
    }

    /// Remove a role from a group. Returns true if removed.
    pub async fn remove_role(&self, group_id: Uuid, role_id: Uuid) -> Result<bool, AppError> {
        let r = sqlx::query(
            "DELETE FROM group_roles WHERE group_id = $1 AND role_id = $2",
        )
        .bind(group_id)
        .bind(role_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Roles assigned to a group. Returns (id, name, uid).
    pub async fn list_group_roles(
        &self,
        tenant_id: &str,
        group_id: Uuid,
    ) -> Result<Vec<(Uuid, String, String)>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid, String, String)>(
            r#"
            SELECT r.id, r.name, r.uid
            FROM roles r
            INNER JOIN group_roles gr ON gr.role_id = r.id
            INNER JOIN groups g ON g.id = gr.group_id
            WHERE gr.group_id = $1 AND g.tenant_id = $2
            ORDER BY r.name
            "#,
        )
        .bind(group_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // ── Effective role/permission queries (used when building sessions) ────────

    /// Role UIDs a user inherits through their group memberships (including ancestor roles).
    pub async fn get_user_group_role_uids(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<String>, AppError> {
        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            WITH RECURSIVE direct_group_roles AS (
                SELECT DISTINCT r.id, r.uid, r.parent_role_id
                FROM roles r
                INNER JOIN group_roles gr ON gr.role_id = r.id
                INNER JOIN user_groups ug ON ug.group_id = gr.group_id
                WHERE ug.user_id = $1 AND r.tenant_id = $2
            ),
            role_ancestors AS (
                SELECT id, uid, parent_role_id FROM direct_group_roles
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

    /// Role primary-key UUIDs a user inherits through their groups (including ancestor roles) — for policy set loading.
    pub async fn get_user_group_role_ids(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, AppError> {
        let rows = sqlx::query_as::<_, (Uuid,)>(
            r#"
            WITH RECURSIVE direct_group_roles AS (
                SELECT DISTINCT r.id, r.parent_role_id
                FROM roles r
                INNER JOIN group_roles gr ON gr.role_id = r.id
                INNER JOIN user_groups ug ON ug.group_id = gr.group_id
                WHERE ug.user_id = $1 AND r.tenant_id = $2
            ),
            role_ancestors AS (
                SELECT id, parent_role_id FROM direct_group_roles
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

    /// Permission names a user inherits through their groups (including ancestor role permissions).
    pub async fn get_user_group_permissions(
        &self,
        tenant_id: &str,
        user_id: Uuid,
    ) -> Result<Vec<String>, AppError> {
        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            WITH RECURSIVE direct_group_roles AS (
                SELECT DISTINCT r.id, r.parent_role_id
                FROM roles r
                INNER JOIN group_roles gr ON gr.role_id = r.id
                INNER JOIN user_groups ug ON ug.group_id = gr.group_id
                WHERE ug.user_id = $1 AND r.tenant_id = $2
            ),
            role_ancestors AS (
                SELECT id, parent_role_id FROM direct_group_roles
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
}
