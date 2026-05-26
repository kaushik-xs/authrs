//! Admin routes: users, roles, permissions, kv_store.

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::state::AppState;
use crate::api::tenant::TenantId;
use crate::error::AppError;
use crate::policy::domain::PermissionDocument;
use crate::policy::engine::{authorize, AuthzRequest};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdminResetPasswordBody {
    new_password: String,
    retype_password: String,
    #[serde(default)]
    force_password_change: bool,
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/users", post(admin_create_user))
        .route("/users", get(admin_list_users))
        .route("/users/:user_id/roles", get(admin_list_user_roles))
        .route("/users/:user_id/roles", post(admin_assign_role_to_user))
        .route("/users/:user_id/roles/:role_id", delete(admin_remove_role_from_user))
        .route("/users/:user_id/archive", post(admin_archive_user))
        .route("/users/:user_id/reset-password", post(admin_reset_password))
        .route("/roles", post(admin_create_role))
        .route("/roles", get(admin_list_roles))
        .route("/roles/:role_id/permissions", post(admin_attach_permission_to_role))
        .route("/roles/:role_id/permissions", get(admin_list_role_permissions))
        .route("/roles/:role_id/permissions/:permission_id", delete(admin_detach_permission_from_role))
        .route("/permissions", post(admin_create_permission))
        .route("/permissions", get(admin_list_permissions))
        .route("/permissions/check", post(admin_check_permission))
        .route("/permissions/:permission_id", get(admin_get_permission))
        .route("/permissions/:permission_id", delete(admin_delete_permission))
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdminCreateUserBody {
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    mobile: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    retype_password: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdminCreateRoleBody {
    name: String,
}

async fn admin_list_user_roles(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(user_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let roles = state
        .auth_service
        .roles_repo()
        .get_user_roles_detail(&tenant_id.0, user_id)
        .await?;
    let roles_json: Vec<serde_json::Value> = roles
        .into_iter()
        .map(|(id, name, uid)| serde_json::json!({ "id": id, "name": name, "uid": uid }))
        .collect();
    Ok(Json(serde_json::json!({ "roles": roles_json })))
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
            body.force_password_change,
        )
        .await?;
    Ok((
        axum::http::StatusCode::OK,
        Json(serde_json::json!({ "message": "Password reset successfully." })),
    ))
}

async fn admin_create_user(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<AdminCreateUserBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let user = state
        .auth_service
        .admin_create_user(
            &tenant_id.0,
            body.first_name.as_deref(),
            body.last_name.as_deref(),
            body.email.as_deref(),
            body.username.as_deref(),
            body.mobile.as_deref(),
            body.country_code.as_deref(),
            body.password.as_deref(),
            body.retype_password.as_deref(),
        )
        .await?;
    let user_json = serde_json::to_value(&user).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(user_json),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListUsersQuery {
    #[serde(default)]
    include_archived: bool,
}

async fn admin_list_users(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Query(params): Query<ListUsersQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let users = state
        .auth_service
        .users_repo()
        .list(&tenant_id.0, params.include_archived)
        .await?;
    let users_json: Vec<serde_json::Value> = users
        .into_iter()
        .map(|u| serde_json::to_value(&u).unwrap_or_default())
        .collect();
    Ok(Json(serde_json::json!({ "users": users_json })))
}

async fn admin_archive_user(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(user_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    state
        .auth_service
        .admin_archive_user(&tenant_id.0, user_id)
        .await?;
    Ok(Json(serde_json::json!({ "message": "User archived successfully." })))
}

async fn admin_create_role(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<AdminCreateRoleBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let (id, name, uid) = state
        .auth_service
        .roles_repo()
        .create(&tenant_id.0, &body.name)
        .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "id": id, "name": name, "uid": uid })),
    ))
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
        .map(|(id, name, uid)| serde_json::json!({ "id": id, "name": name, "uid": uid }))
        .collect();
    Ok(Json(serde_json::json!({ "roles": roles_json })))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatePermissionBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    document: PermissionDocument,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttachPermissionBody {
    permission_id: Uuid,
}

async fn admin_create_permission(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<CreatePermissionBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let resolved_doc = state
        .permissions_service
        .resolve_principals(&tenant_id.0, &body.document)
        .await?;

    // Validate by compiling — reject invalid documents before saving
    crate::policy::compiler::compile(&resolved_doc, "validation-pass")
        .map_err(|e| AppError::BadRequest(format!("Invalid permission document: {e}")))?;

    let id = state
        .permissions_service
        .repo()
        .create(
            &tenant_id.0,
            &body.name,
            body.description.as_deref(),
            &resolved_doc,
        )
        .await?;

    state.permissions_service.evict(&tenant_id.0);

    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "id": id, "name": body.name })),
    ))
}

async fn admin_list_permissions(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
) -> Result<Json<serde_json::Value>, AppError> {
    let perms = state
        .permissions_service
        .repo()
        .list(&tenant_id.0)
        .await?;
    let out: Vec<serde_json::Value> = perms
        .into_iter()
        .map(|(id, name, desc, doc)| {
            serde_json::json!({ "id": id, "name": name, "description": desc, "document": doc })
        })
        .collect();
    Ok(Json(serde_json::json!({ "permissions": out })))
}

async fn admin_get_permission(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(permission_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (name, desc, doc) = state
        .permissions_service
        .repo()
        .get(&tenant_id.0, permission_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Permission not found".to_string()))?;
    Ok(Json(
        serde_json::json!({ "id": permission_id, "name": name, "description": desc, "document": doc }),
    ))
}

async fn admin_delete_permission(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(permission_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let deleted = state
        .permissions_service
        .repo()
        .delete(&tenant_id.0, permission_id)
        .await?;
    if !deleted {
        return Err(AppError::NotFound("Permission not found".to_string()));
    }
    state.permissions_service.evict(&tenant_id.0);
    Ok(Json(serde_json::json!({ "message": "Permission deleted" })))
}

async fn admin_attach_permission_to_role(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(role_id): Path<Uuid>,
    Json(body): Json<AttachPermissionBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    state
        .permissions_service
        .repo()
        .attach_to_role(&tenant_id.0, role_id, body.permission_id)
        .await?;
    state.permissions_service.evict(&tenant_id.0);
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "message": "Permission attached to role" })),
    ))
}

async fn admin_detach_permission_from_role(
    State(state): State<Arc<AppState>>,
    Path((role_id, permission_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let removed = state
        .permissions_service
        .repo()
        .detach_from_role(role_id, permission_id)
        .await?;
    if !removed {
        return Err(AppError::NotFound(
            "Permission-role assignment not found".to_string(),
        ));
    }
    Ok(Json(serde_json::json!({ "message": "Permission detached from role" })))
}

async fn admin_list_role_permissions(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(role_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let perms = state
        .permissions_service
        .repo()
        .list_for_role(&tenant_id.0, role_id)
        .await?;
    let out: Vec<serde_json::Value> = perms
        .into_iter()
        .map(|(id, name, doc)| serde_json::json!({ "id": id, "name": name, "document": doc }))
        .collect();
    Ok(Json(serde_json::json!({ "permissions": out })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckPermissionBody {
    user_id: Uuid,
    resource: String,
    /// If provided, evaluate only this action.
    /// If omitted, evaluate all actions relevant to the resource scope.
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    context: Option<serde_json::Value>,
}

async fn admin_check_permission(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<CheckPermissionBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    tracing::info!(
        tenant_id = %tenant_id.0,
        user_id = %body.user_id,
        resource = %body.resource,
        action = ?body.action,
        "permission check request"
    );

    let role_names = state
        .auth_service
        .roles_repo()
        .get_user_roles(&tenant_id.0, body.user_id)
        .await?;

    tracing::debug!(
        tenant_id = %tenant_id.0,
        user_id = %body.user_id,
        roles = ?role_names,
        "resolved user roles"
    );

    let context = body.context.unwrap_or_else(|| serde_json::json!({}));
    let resource = body.resource.clone();

    // Load PolicySet outside any lock — safe across await
    let policy_set = state
        .permissions_service
        .get_policy_set(&tenant_id.0)
        .await?;

    if let Some(action) = body.action {
        let allowed = {
            let schema = state.cedar_schema.read().unwrap();
            is_allowed(&AuthzRequest {
                user_id: body.user_id,
                role_names: &role_names,
                action: &action,
                resource: &resource,
                context,
            }, &policy_set, &schema)
        };
        tracing::info!(
            tenant_id = %tenant_id.0,
            user_id = %body.user_id,
            resource = %resource,
            action = %action,
            allowed,
            "permission decision"
        );
        return Ok(Json(serde_json::json!({
            "resource": resource,
            "action": action,
            "allowed": allowed,
        })));
    }

    // All-actions check: fetch relevant actions then evaluate each
    let actions = state
        .packages_service
        .get_actions_for_resource(&resource)
        .await?;

    let mut decisions: HashMap<String, bool> = HashMap::new();
    {
        let schema = state.cedar_schema.read().unwrap();
        for action in &actions {
            let allowed = is_allowed(&AuthzRequest {
                user_id: body.user_id,
                role_names: &role_names,
                action,
                resource: &resource,
                context: context.clone(),
            }, &policy_set, &schema);
            decisions.insert(action.clone(), allowed);
        }
    }

    tracing::info!(
        tenant_id = %tenant_id.0,
        user_id = %body.user_id,
        resource = %resource,
        decisions = ?decisions,
        "permission decisions (all actions)"
    );

    Ok(Json(serde_json::json!({
        "resource": resource,
        "decisions": decisions,
    })))
}

fn is_allowed(req: &AuthzRequest, policy_set: &cedar_policy::PolicySet, schema: &cedar_policy::Schema) -> bool {
    matches!(authorize(req, policy_set, schema), cedar_policy::Decision::Allow)
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