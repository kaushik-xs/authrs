//! Repository for _auth_packages and _auth_package_actions.

use crate::error::AppError;
use sqlx::PgPool;

#[derive(Clone)]
pub struct PackagesRepo {
    pool: PgPool,
}

impl PackagesRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Replace all tables for a package (full sync).
    pub async fn sync_tables(
        &self,
        package_id: &str,
        table_names: &[String],
    ) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM _auth_packages WHERE package_id = $1")
            .bind(package_id)
            .execute(&mut *tx)
            .await?;

        for table_name in table_names {
            sqlx::query(
                "INSERT INTO _auth_packages (package_id, table_name) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(package_id)
            .bind(table_name)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Replace all custom actions for a package (full sync).
    pub async fn sync_custom_actions(
        &self,
        package_id: &str,
        action_names: &[String],
    ) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM _auth_package_actions WHERE package_id = $1")
            .bind(package_id)
            .execute(&mut *tx)
            .await?;

        for action_name in action_names {
            sqlx::query(
                "INSERT INTO _auth_package_actions (package_id, action_name) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(package_id)
            .bind(action_name)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Load all (package_id, table_name) pairs.
    pub async fn list_tables(&self) -> Result<Vec<(String, String)>, AppError> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT package_id, table_name FROM _auth_packages ORDER BY package_id, table_name",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Load all (package_id, action_name) pairs.
    pub async fn list_custom_actions(&self) -> Result<Vec<(String, String)>, AppError> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT package_id, action_name FROM _auth_package_actions ORDER BY package_id, action_name",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}
