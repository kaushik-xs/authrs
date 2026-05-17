//! Database seeder: creates base data from user input (env vars).
//! Run with: cargo run --bin seed (after setting SEED_* env vars).

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use sqlx::PgPool;
use uuid::Uuid;

/// User-provided seed input (from environment).
#[derive(Clone, Debug)]
pub struct SeedInput {
    /// Tenant id (lower snake_case, e.g. acme_corp).
    pub tenant_id: String,
    /// Tenant display name.
    pub tenant_name: String,
    /// Role name to create and assign to admin user (e.g. "Launchpad Admin").
    pub role_name: String,
    /// Optional: create an admin user with this email (assign role via user_roles).
    pub admin_email: Option<String>,
    /// Optional: admin user password (required if admin_email is set).
    pub admin_password: Option<String>,
    /// Optional: admin first name.
    pub admin_first_name: Option<String>,
    /// Optional: admin last name.
    pub admin_last_name: Option<String>,
}

impl SeedInput {
    /// Load from environment. Returns None if SEED_TENANT_ID is not set (seed disabled).
    pub fn from_env() -> Result<Option<Self>, String> {
        let tenant_id = match std::env::var("SEED_TENANT_ID").ok().filter(|s| !s.is_empty()) {
            Some(v) => v,
            None => return Ok(None),
        };
        let tenant_name = std::env::var("SEED_TENANT_NAME")
            .unwrap_or_else(|_| tenant_id.replace('_', " ").to_string());
        let role_name = std::env::var("SEED_ROLE_NAME").unwrap_or_else(|_| "Launchpad Admin".to_string());
        let admin_email = std::env::var("SEED_ADMIN_EMAIL").ok().filter(|s| !s.is_empty());
        let admin_password = std::env::var("SEED_ADMIN_PASSWORD").ok().filter(|s| !s.is_empty());
        let admin_first_name = std::env::var("SEED_ADMIN_FIRST_NAME").ok().filter(|s| !s.is_empty());
        let admin_last_name = std::env::var("SEED_ADMIN_LAST_NAME").ok().filter(|s| !s.is_empty());

        if admin_email.is_some() && admin_password.as_ref().map_or(true, |p| p.is_empty()) {
            return Err("SEED_ADMIN_PASSWORD is required when SEED_ADMIN_EMAIL is set".to_string());
        }

        Ok(Some(Self {
            tenant_id,
            tenant_name,
            role_name,
            admin_email,
            admin_password,
            admin_first_name,
            admin_last_name,
        }))
    }
}

fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Run the seeder: tenant, role, optional admin user (with role assigned via user_roles).
pub async fn run(pool: &PgPool, input: &SeedInput) -> Result<(), String> {
    // 1. Tenant (idempotent)
    let inserted = sqlx::query(
        r#"
        INSERT INTO tenants (id, name, status)
        VALUES ($1, $2, 'active')
        ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
        "#,
    )
    .bind(&input.tenant_id)
    .bind(&input.tenant_name)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;

    tracing::info!(
        "Tenant {} ({})",
        input.tenant_id,
        if inserted.rows_affected() > 0 {
            "created or updated"
        } else {
            "already exists"
        }
    );

    // 2. Seeded role (SEED_ROLE_NAME)
    let _ = sqlx::query(
        r#"
        INSERT INTO roles (tenant_id, name)
        SELECT $1, $2
        WHERE NOT EXISTS (
            SELECT 1 FROM roles r
            WHERE r.tenant_id = $1 AND r.name = $2
        )
        "#,
    )
    .bind(&input.tenant_id)
    .bind(&input.role_name)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;

    // 3. Optional admin user (assign role via user_roles)
    if let (Some(email), Some(password)) = (&input.admin_email, &input.admin_password) {
        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Err("SEED_ADMIN_EMAIL cannot be empty".to_string());
        }

        let password_hash = hash_password(password)?;
        let first_name = input.admin_first_name.as_deref().unwrap_or("Admin").to_string();
        let last_name = input.admin_last_name.as_deref().unwrap_or("User").to_string();
        let now = chrono::Utc::now();

        let user_id = Uuid::new_v4();
        let inserted_user = sqlx::query(
            r#"
            INSERT INTO users (id, tenant_id, first_name, last_name, email, username, mobile, country_code, password_hash, status, mfa_enabled, failed_attempts, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, NULL, NULL, NULL, $6, 'active', false, 0, $7, $7)
            ON CONFLICT (tenant_id, email) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(&input.tenant_id)
        .bind(&first_name)
        .bind(&last_name)
        .bind(&email)
        .bind(&password_hash)
        .bind(now)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;

        if inserted_user.rows_affected() > 0 {
            tracing::info!("Admin user {} created for tenant {}", email, input.tenant_id);
        } else {
            tracing::info!("Admin user {} already exists for tenant {}", email, input.tenant_id);
        }

        // Resolve user id (new or existing) and add to Launchpad Admins group
        let existing_user_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM users WHERE tenant_id = $1 AND email = $2",
        )
        .bind(&input.tenant_id)
        .bind(&email)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;

        if let Some(uid) = existing_user_id {
            let role_id: Uuid = sqlx::query_scalar(
                "SELECT id FROM roles WHERE tenant_id = $1 AND name = $2",
            )
            .bind(&input.tenant_id)
            .bind(&input.role_name)
            .fetch_one(pool)
            .await
            .map_err(|e| e.to_string())?;

            sqlx::query(
                r#"
                INSERT INTO user_roles (user_id, role_id)
                VALUES ($1, $2)
                ON CONFLICT (user_id, role_id) DO NOTHING
                "#,
            )
            .bind(uid)
            .bind(role_id)
            .execute(pool)
            .await
            .map_err(|e| e.to_string())?;

            tracing::info!("Admin user assigned role '{}'", input.role_name);
        }
    }

    Ok(())
}
