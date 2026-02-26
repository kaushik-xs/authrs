//! Tenant repository.

use crate::domain::tenant::Tenant;
use crate::error::AppError;
use sqlx::{FromRow, PgPool};

#[derive(FromRow)]
struct TenantRow {
    id: String,
    name: String,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct TenantsRepo {
    pool: PgPool,
}

impl TenantsRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_by_id(&self, id: &str) -> Result<Option<Tenant>, AppError> {
        let row = sqlx::query_as::<_, TenantRow>(
            "SELECT id, name, status, created_at FROM tenants WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| Tenant {
            id: r.id,
            name: r.name,
            status: r.status,
            created_at: r.created_at,
        }))
    }
}
