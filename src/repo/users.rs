//! Membership repository. A `users` row is a per-tenant membership of a global identity
//! (`identity_id`). Display fields (name/email/mobile) and `mfa_enabled` live on the
//! `identities` row and are joined in for reads; the membership row itself holds only
//! `identity_id`, `username`, `status`, and `access_valid_until`.

use crate::domain::identity::Identity;
use crate::domain::user::User;
use crate::error::AppError;
use crate::query::{self, FieldSpec, FieldType, FilterNode, SortSpec};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// RSQL-filterable/sortable fields for `GET /admin/users`. Names are the camelCase JSON
/// keys clients see in responses; columns are qualified against the `u`/`i` aliases used
/// by `SELECT_COLS`. `password_hash` / `mfa_secret` are listed as `sensitive` so filtering
/// or sorting on them is rejected with a 422 rather than a vague "unknown field".
pub const USER_FILTER_FIELDS: &[FieldSpec] = &[
    FieldSpec { api_name: "id", column: "u.id", ty: FieldType::Uuid, sensitive: false },
    FieldSpec { api_name: "identityId", column: "u.identity_id", ty: FieldType::Uuid, sensitive: false },
    FieldSpec { api_name: "firstName", column: "i.first_name", ty: FieldType::Text, sensitive: false },
    FieldSpec { api_name: "lastName", column: "i.last_name", ty: FieldType::Text, sensitive: false },
    FieldSpec { api_name: "email", column: "i.email", ty: FieldType::Text, sensitive: false },
    FieldSpec { api_name: "username", column: "u.username", ty: FieldType::Text, sensitive: false },
    FieldSpec { api_name: "mobile", column: "i.mobile", ty: FieldType::Text, sensitive: false },
    FieldSpec { api_name: "countryCode", column: "i.country_code", ty: FieldType::Text, sensitive: false },
    FieldSpec { api_name: "status", column: "u.status", ty: FieldType::Text, sensitive: false },
    FieldSpec { api_name: "mfaEnabled", column: "i.mfa_enabled", ty: FieldType::Bool, sensitive: false },
    FieldSpec { api_name: "accessValidUntil", column: "u.access_valid_until", ty: FieldType::Timestamp, sensitive: false },
    FieldSpec { api_name: "createdAt", column: "u.created_at", ty: FieldType::Timestamp, sensitive: false },
    FieldSpec { api_name: "updatedAt", column: "u.updated_at", ty: FieldType::Timestamp, sensitive: false },
    // Sensitive identity columns — never filterable/sortable.
    FieldSpec { api_name: "passwordHash", column: "i.password_hash", ty: FieldType::Text, sensitive: true },
    FieldSpec { api_name: "mfaSecret", column: "i.mfa_secret", ty: FieldType::Text, sensitive: true },
];

/// Select list + join used by every membership read. `u` = users, `i` = identities.
const SELECT_COLS: &str = "u.id, u.tenant_id, u.identity_id, i.first_name, i.last_name, \
                           i.email, u.username, i.mobile, i.country_code, u.status, \
                           i.mfa_enabled, u.access_valid_until, u.created_at, u.updated_at";
const FROM_JOIN: &str = "FROM users u JOIN identities i ON i.id = u.identity_id";

#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    tenant_id: String,
    identity_id: Uuid,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    username: Option<String>,
    mobile: Option<String>,
    country_code: Option<String>,
    status: String,
    mfa_enabled: bool,
    access_valid_until: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct UsersRepo {
    pool: PgPool,
}

impl UsersRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_user(r: UserRow) -> User {
        User {
            id: r.id,
            tenant_id: r.tenant_id,
            identity_id: r.identity_id,
            first_name: r.first_name,
            last_name: r.last_name,
            email: r.email,
            username: r.username,
            mobile: r.mobile,
            country_code: r.country_code,
            status: r.status,
            mfa_enabled: r.mfa_enabled,
            access_valid_until: r.access_valid_until,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }

    /// Create a membership row linking an identity to a tenant. Display fields come from the
    /// identity; only `username` is per-tenant.
    pub async fn create(
        &self,
        identity: &Identity,
        tenant_id: &str,
        username: Option<&str>,
    ) -> Result<User, AppError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        sqlx::query(
            r#"INSERT INTO users (id, tenant_id, identity_id, username, status, created_at, updated_at)
               VALUES ($1, $2, $3, $4, 'active', $5, $5)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identity.id)
        .bind(username)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(User {
            id,
            tenant_id: tenant_id.to_string(),
            identity_id: identity.id,
            first_name: identity.first_name.clone(),
            last_name: identity.last_name.clone(),
            email: identity.email.clone(),
            username: username.map(String::from),
            mobile: identity.mobile.clone(),
            country_code: identity.country_code.clone(),
            status: "active".to_string(),
            mfa_enabled: identity.mfa_enabled,
            access_valid_until: None,
            created_at: now,
            updated_at: now,
        })
    }

    /// List memberships for a tenant. Excludes archived unless requested. Supports optional
    /// RSQL `filter` and `sort` (validated against [`USER_FILTER_FIELDS`]) plus `limit`/`offset`.
    /// With no `sort`, falls back to newest-first (`created_at DESC`).
    pub async fn list(
        &self,
        tenant_id: &str,
        include_archived: bool,
        filter: Option<&FilterNode>,
        sort: &[SortSpec],
        limit: u32,
        offset: u32,
    ) -> Result<Vec<User>, AppError> {
        // tenant_id is $1; RSQL params begin at $2.
        let built = query::build(filter, sort, USER_FILTER_FIELDS, 2)?;

        let mut where_sql = String::from("u.tenant_id = $1");
        if !include_archived {
            where_sql.push_str(" AND u.status != 'archived'");
        }
        if !built.where_sql.is_empty() {
            where_sql.push_str(" AND ");
            where_sql.push_str(&built.where_sql);
        }
        let order_sql = if built.order_sql.is_empty() {
            " ORDER BY u.created_at DESC".to_string()
        } else {
            built.order_sql
        };
        let sql = format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE {where_sql}{order_sql} LIMIT {limit} OFFSET {offset}"
        );

        let mut q = sqlx::query_as::<_, UserRow>(&sql).bind(tenant_id);
        for p in &built.params {
            q = q.bind(p);
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(Self::row_to_user).collect())
    }

    /// Full membership rows for the members of a group. Same shape as [`list`], joined through
    /// `user_groups`. Supports optional RSQL `filter`/`sort` (validated against
    /// [`USER_FILTER_FIELDS`]) plus `limit`/`offset` — so callers can pull a specific member by
    /// e.g. `username==...`, `firstName==...`, or `email==...`. With no `sort`, orders by the
    /// membership's `created_at` in the group (join time) ascending.
    pub async fn list_by_group(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        filter: Option<&FilterNode>,
        sort: &[SortSpec],
        limit: u32,
        offset: u32,
    ) -> Result<Vec<User>, AppError> {
        // tenant_id is $1, group_id is $2; RSQL params begin at $3.
        let built = query::build(filter, sort, USER_FILTER_FIELDS, 3)?;

        let mut where_sql = String::from("u.tenant_id = $1 AND ug.group_id = $2");
        if !built.where_sql.is_empty() {
            where_sql.push_str(" AND ");
            where_sql.push_str(&built.where_sql);
        }
        let order_sql = if built.order_sql.is_empty() {
            " ORDER BY ug.created_at ASC".to_string()
        } else {
            built.order_sql
        };
        let sql = format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} \
             JOIN user_groups ug ON ug.user_id = u.id \
             WHERE {where_sql}{order_sql} LIMIT {limit} OFFSET {offset}"
        );

        let mut q = sqlx::query_as::<_, UserRow>(&sql)
            .bind(tenant_id)
            .bind(group_id);
        for p in &built.params {
            q = q.bind(p);
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(Self::row_to_user).collect())
    }

    pub async fn archive(&self, tenant_id: &str, user_id: Uuid) -> Result<bool, AppError> {
        let result = sqlx::query(
            "UPDATE users SET status = 'archived', updated_at = now() WHERE tenant_id = $1 AND id = $2 AND status != 'archived'",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_by_id(&self, tenant_id: &str, user_id: Uuid) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.tenant_id = $1 AND u.id = $2"
        ))
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    /// The single membership of an identity within a tenant (the SSO select-tenant path).
    pub async fn get_membership(
        &self,
        identity_id: Uuid,
        tenant_id: &str,
    ) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.identity_id = $1 AND u.tenant_id = $2"
        ))
        .bind(identity_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    /// All memberships of an identity across tenants (the identity's tenant list).
    pub async fn get_memberships_for_identity(&self, identity_id: Uuid) -> Result<Vec<User>, AppError> {
        let rows = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.identity_id = $1 AND u.status != 'archived' ORDER BY u.created_at"
        ))
        .bind(identity_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Self::row_to_user).collect())
    }

    /// Membership in a tenant whose identity has the given email (per-tenant existence check).
    pub async fn get_by_email(&self, tenant_id: &str, email: &str) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.tenant_id = $1 AND i.email = $2"
        ))
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    /// Case-insensitive variant. Used for OTP verify.
    pub async fn get_by_email_insensitive(&self, tenant_id: &str, email: &str) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.tenant_id = $1 AND LOWER(i.email) = LOWER($2)"
        ))
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    pub async fn get_by_username(&self, tenant_id: &str, username: &str) -> Result<Option<User>, AppError> {
        let row = sqlx::query_as::<_, UserRow>(&format!(
            "SELECT {SELECT_COLS} {FROM_JOIN} WHERE u.tenant_id = $1 AND u.username = $2"
        ))
        .bind(tenant_id)
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Self::row_to_user))
    }

    pub async fn set_access_valid_until(
        &self,
        tenant_id: &str,
        user_id: Uuid,
        access_valid_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE users SET access_valid_until = $1, updated_at = now() WHERE tenant_id = $2 AND id = $3",
        )
        .bind(access_valid_until)
        .bind(tenant_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn exists_by_username(&self, tenant_id: &str, username: &str) -> Result<bool, AppError> {
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id = $1 AND username = $2)",
        )
        .bind(tenant_id)
        .bind(username)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }
}
