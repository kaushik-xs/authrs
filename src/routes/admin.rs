//! Admin routes: users, roles, permissions, kv_store.

use axum::{
    extract::{Path, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::state::AppState;
use crate::api::tenant::TenantId;
use crate::error::AppError;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdminResetPasswordBody {
    new_password: String,
    retype_password: String,
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/users", post(admin_create_user))
        .route("/users", get(admin_list_users))
        .route("/users/:user_id/roles", get(admin_list_user_roles))
        .route("/users/:user_id/roles", post(admin_assign_role_to_user))
        .route("/users/:user_id/roles/:role_id", delete(admin_remove_role_from_user))
        .route("/users/:user_id/reset-password", post(admin_reset_password))
        .route("/roles", post(admin_create_role))
        .route("/roles", get(admin_list_roles))
        .route("/permissions", post(admin_create_permission))
        .route("/permissions", get(admin_list_permissions))
        .route("/kv_store", get(admin_kv_list))
        .route("/kv_store/:group_key/:key", get(admin_kv_get))
        .route("/kv_store/:group_key/:key", put(admin_kv_put))
        .route("/kv_store/:group_key/:key", delete(admin_kv_delete))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssignRoleBody {
    role_id: Uuid,
}

async fn admin_list_user_roles(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(user_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let roles = state
        .auth_service
        .roles_repo()
        .get_user_roles(&tenant_id.0, user_id)
        .await?;
    Ok(Json(serde_json::json!({ "roles": roles })))
}

async fn admin_assign_role_to_user(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(user_id): Path<Uuid>,
    Json(body): Json<AssignRoleBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    state
        .auth_service
        .roles_repo()
        .assign_role_to_user(&tenant_id.0, user_id, body.role_id)
        .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "message": "Role assigned to user" })),
    ))
}

async fn admin_remove_role_from_user(
    State(state): State<Arc<AppState>>,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let removed = state
        .auth_service
        .roles_repo()
        .remove_role_from_user(user_id, role_id)
        .await?;
    if !removed {
        return Err(AppError::NotFound("User role assignment not found".to_string()));
    }
    Ok(Json(serde_json::json!({ "message": "Role removed from user" })))
}

async fn admin_reset_password(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(user_id): Path<Uuid>,
    Json(body): Json<AdminResetPasswordBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    state
        .auth_service
        .admin_reset_password(
            &tenant_id.0,
            user_id,
            &body.new_password,
            &body.retype_password,
        )
        .await?;
    Ok((
        axum::http::StatusCode::OK,
        Json(serde_json::json!({ "message": "Password reset successfully." })),
    ))
}

async fn admin_create_user() -> &'static str {
    "admin create user placeholder"
}
async fn admin_list_users() -> &'static str {
    "admin list users placeholder"
}
async fn admin_create_role() -> &'static str {
    "admin create role placeholder"
}
async fn admin_list_roles(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
) -> Result<Json<serde_json::Value>, AppError> {
    let roles = state
        .auth_service
        .roles_repo()
        .list_roles(&tenant_id.0)
        .await?;
    let roles_json: Vec<serde_json::Value> = roles
        .into_iter()
        .map(|(id, name)| serde_json::json!({ "id": id, "name": name }))
        .collect();
    Ok(Json(serde_json::json!({ "roles": roles_json })))
}
async fn admin_create_permission() -> &'static str {
    "admin create permission placeholder"
}
async fn admin_list_permissions() -> &'static str {
    "admin list permissions placeholder"
}
async fn admin_kv_list() -> &'static str {
    "admin kv list placeholder"
}
async fn admin_kv_get() -> &'static str {
    "admin kv get placeholder"
}
async fn admin_kv_put() -> &'static str {
    "admin kv put placeholder"
}
async fn admin_kv_delete() -> &'static str {
    "admin kv delete placeholder"
}