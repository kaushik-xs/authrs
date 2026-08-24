//! Admin routes: users, roles, permissions, kv_store.

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, patch, post, put},
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
struct AdminSetAccessValidityBody {
    access_valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

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
        .route("/users/:user_id/groups", get(admin_list_user_groups))
        .route("/users/:user_id/archive", post(admin_archive_user))
        .route("/users/:user_id/reset-password", post(admin_reset_password))
        .route("/users/:user_id/access-validity", patch(admin_set_access_validity))
        .route("/roles", post(admin_create_role))
        .route("/roles", get(admin_list_roles))
        .route("/roles/:role_id", delete(admin_delete_role))
        .route("/roles/:role_id/parent", put(admin_set_role_parent))
        .route("/roles/:role_id/hierarchy", get(admin_get_role_hierarchy))
        .route("/roles/:role_id/permissions", post(admin_attach_permission_to_role))
        .route("/roles/:role_id/permissions", get(admin_list_role_permissions))
        .route("/roles/:role_id/permissions/:permission_id", delete(admin_detach_permission_from_role))
        .route("/groups", post(admin_create_group))
        .route("/groups", get(admin_list_groups))
        .route("/groups/:group_id", get(admin_get_group))
        .route("/groups/:group_id", delete(admin_delete_group))
        .route("/groups/:group_id/users", post(admin_add_user_to_group))
        .route("/groups/:group_id/users", get(admin_list_group_members))
        .route("/groups/:group_id/users/:user_id", delete(admin_remove_user_from_group))
        .route("/groups/:group_id/roles", post(admin_assign_role_to_group))
        .route("/groups/:group_id/roles", get(admin_list_group_roles))
        .route("/groups/:group_id/roles/:role_id", delete(admin_remove_role_from_group))
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
    #[serde(default)]
    parent_role_id: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdminSetRoleParentBody {
    parent_role_id: Option<Uuid>,
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

/// Common list query params for RSQL-capable list endpoints: `q` (RSQL filter),
/// `sort`, and `limit`/`offset` pagination.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ListQuery {
    q: Option<String>,
    sort: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListUsersQuery {
    #[serde(default)]
    include_archived: bool,
    q: Option<String>,
    sort: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

async fn admin_list_users(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Query(params): Query<ListUsersQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (filter, sort) =
        crate::query::parse_list_params(params.q.as_deref(), params.sort.as_deref())?;
    let (limit, offset) = crate::query::clamp_pagination(params.limit, params.offset, 50);
    let users = state
        .auth_service
        .users_repo()
        .list(
            &tenant_id.0,
            params.include_archived,
            filter.as_ref(),
            &sort,
            limit,
            offset,
        )
        .await?;
    let users_json: Vec<serde_json::Value> = users
        .into_iter()
        .map(|u| serde_json::to_value(&u).unwrap_or_default())
        .collect();
    Ok(Json(serde_json::json!({ "users": users_json })))
}

async fn admin_set_access_validity(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(user_id): Path<Uuid>,
    Json(body): Json<AdminSetAccessValidityBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    state
        .auth_service
        .admin_set_access_valid_until(&tenant_id.0, user_id, body.access_valid_until)
        .await?;
    Ok(Json(serde_json::json!({ "message": "Access validity updated." })))
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
        .create(&tenant_id.0, &body.name, body.parent_role_id)
        .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "id": id, "name": name, "uid": uid, "parentRoleId": body.parent_role_id })),
    ))
}

async fn admin_list_roles(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Query(params): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (filter, sort) = crate::query::parse_list_params(params.q.as_deref(), params.sort.as_deref())?;
    let (limit, offset) = crate::query::clamp_pagination(params.limit, params.offset, 50);
    let roles = state
        .auth_service
        .roles_repo()
        .list_roles(&tenant_id.0, filter.as_ref(), &sort, limit, offset)
        .await?;
    let roles_json: Vec<serde_json::Value> = roles
        .into_iter()
        .map(|(id, name, uid, parent_role_id)| {
            serde_json::json!({ "id": id, "name": name, "uid": uid, "parentRoleId": parent_role_id })
        })
        .collect();
    Ok(Json(serde_json::json!({ "roles": roles_json })))
}

async fn admin_set_role_parent(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(role_id): Path<Uuid>,
    Json(body): Json<AdminSetRoleParentBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    state
        .auth_service
        .roles_repo()
        .set_parent(&tenant_id.0, role_id, body.parent_role_id)
        .await?;
    Ok(Json(serde_json::json!({ "message": "Role parent updated." })))
}

async fn admin_delete_role(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(role_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let deleted = state
        .auth_service
        .roles_repo()
        .delete(&tenant_id.0, role_id)
        .await?;
    if !deleted {
        return Err(AppError::NotFound("Role not found".to_string()));
    }
    // Deleting a role removes its role_permissions links and changes permission
    // resolution for affected principals — drop any cached permission state.
    state.permissions_service.evict(&tenant_id.0);
    Ok(Json(serde_json::json!({ "message": "Role deleted" })))
}

async fn admin_get_role_hierarchy(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(role_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let ancestors = state
        .auth_service
        .roles_repo()
        .get_role_ancestors(&tenant_id.0, role_id)
        .await?;
    let ancestors_json: Vec<serde_json::Value> = ancestors
        .into_iter()
        .map(|(id, name, uid)| serde_json::json!({ "id": id, "name": name, "uid": uid }))
        .collect();
    Ok(Json(serde_json::json!({ "ancestors": ancestors_json })))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatePermissionBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    document: PermissionDocument,
    /// When true, an existing permission with the same (tenant, name) is overwritten
    /// in place (its Cedar document is replaced) instead of failing on the unique
    /// constraint. Used by the RBAC sync flows so re-syncing is idempotent.
    #[serde(default)]
    overwrite: bool,
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

    let repo = state.permissions_service.repo();
    let id = if body.overwrite {
        repo.upsert(
            &tenant_id.0,
            &body.name,
            body.description.as_deref(),
            &resolved_doc,
        )
        .await?
    } else {
        repo.create(
            &tenant_id.0,
            &body.name,
            body.description.as_deref(),
            &resolved_doc,
        )
        .await?
    };

    state.permissions_service.evict(&tenant_id.0);

    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "id": id, "name": body.name })),
    ))
}

async fn admin_list_permissions(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Query(params): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (filter, sort) = crate::query::parse_list_params(params.q.as_deref(), params.sort.as_deref())?;
    let (limit, offset) = crate::query::clamp_pagination(params.limit, params.offset, 50);
    let perms = state
        .permissions_service
        .repo()
        .list(&tenant_id.0, filter.as_ref(), &sort, limit, offset)
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

// ── Group handlers ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateGroupBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddUserToGroupBody {
    user_id: Uuid,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssignRoleToGroupBody {
    role_id: Uuid,
}

async fn admin_create_group(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<CreateGroupBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let (id, name, uid) = state
        .auth_service
        .groups_repo()
        .create(&tenant_id.0, &body.name, body.description.as_deref())
        .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "id": id, "name": name, "uid": uid })),
    ))
}

async fn admin_list_groups(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Query(params): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (filter, sort) = crate::query::parse_list_params(params.q.as_deref(), params.sort.as_deref())?;
    let (limit, offset) = crate::query::clamp_pagination(params.limit, params.offset, 50);
    let groups = state
        .auth_service
        .groups_repo()
        .list(&tenant_id.0, filter.as_ref(), &sort, limit, offset)
        .await?;
    let out: Vec<serde_json::Value> = groups
        .into_iter()
        .map(|(id, name, uid, desc)| {
            serde_json::json!({ "id": id, "name": name, "uid": uid, "description": desc })
        })
        .collect();
    Ok(Json(serde_json::json!({ "groups": out })))
}

async fn admin_get_group(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(group_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (name, uid, desc) = state
        .auth_service
        .groups_repo()
        .get(&tenant_id.0, group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;
    Ok(Json(
        serde_json::json!({ "id": group_id, "name": name, "uid": uid, "description": desc }),
    ))
}

async fn admin_delete_group(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(group_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let deleted = state
        .auth_service
        .groups_repo()
        .delete(&tenant_id.0, group_id)
        .await?;
    if !deleted {
        return Err(AppError::NotFound("Group not found".to_string()));
    }
    Ok(Json(serde_json::json!({ "message": "Group deleted" })))
}

async fn admin_add_user_to_group(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(group_id): Path<Uuid>,
    Json(body): Json<AddUserToGroupBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    state
        .auth_service
        .groups_repo()
        .add_user(&tenant_id.0, group_id, body.user_id)
        .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "message": "User added to group" })),
    ))
}

async fn admin_list_group_members(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(group_id): Path<Uuid>,
    Query(params): Query<ListUsersQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (filter, sort) =
        crate::query::parse_list_params(params.q.as_deref(), params.sort.as_deref())?;
    let (limit, offset) = crate::query::clamp_pagination(params.limit, params.offset, 50);
    let users = state
        .auth_service
        .users_repo()
        .list_by_group(&tenant_id.0, group_id, filter.as_ref(), &sort, limit, offset)
        .await?;
    let users_json: Vec<serde_json::Value> = users
        .into_iter()
        .map(|u| serde_json::to_value(&u).unwrap_or_default())
        .collect();
    Ok(Json(serde_json::json!({ "users": users_json })))
}

async fn admin_remove_user_from_group(
    State(state): State<Arc<AppState>>,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let removed = state
        .auth_service
        .groups_repo()
        .remove_user(group_id, user_id)
        .await?;
    if !removed {
        return Err(AppError::NotFound("User is not a member of this group".to_string()));
    }
    Ok(Json(serde_json::json!({ "message": "User removed from group" })))
}

async fn admin_list_user_groups(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(user_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let groups = state
        .auth_service
        .groups_repo()
        .get_user_groups(&tenant_id.0, user_id)
        .await?;
    let out: Vec<serde_json::Value> = groups
        .into_iter()
        .map(|(id, name, uid)| serde_json::json!({ "id": id, "name": name, "uid": uid }))
        .collect();
    Ok(Json(serde_json::json!({ "groups": out })))
}

async fn admin_assign_role_to_group(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(group_id): Path<Uuid>,
    Json(body): Json<AssignRoleToGroupBody>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    state
        .auth_service
        .groups_repo()
        .assign_role(&tenant_id.0, group_id, body.role_id)
        .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "message": "Role assigned to group" })),
    ))
}

async fn admin_list_group_roles(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(group_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let roles = state
        .auth_service
        .groups_repo()
        .list_group_roles(&tenant_id.0, group_id)
        .await?;
    let out: Vec<serde_json::Value> = roles
        .into_iter()
        .map(|(id, name, uid)| serde_json::json!({ "id": id, "name": name, "uid": uid }))
        .collect();
    Ok(Json(serde_json::json!({ "roles": out })))
}

async fn admin_remove_role_from_group(
    State(state): State<Arc<AppState>>,
    Path((group_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let removed = state
        .auth_service
        .groups_repo()
        .remove_role(group_id, role_id)
        .await?;
    if !removed {
        return Err(AppError::NotFound("Role is not assigned to this group".to_string()));
    }
    Ok(Json(serde_json::json!({ "message": "Role removed from group" })))
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

    let (role_names, role_ids) = {
        let roles_repo  = state.auth_service.roles_repo();
        let groups_repo = state.auth_service.groups_repo();

        let direct_names = roles_repo.get_user_roles(&tenant_id.0, body.user_id).await?;
        let direct_ids   = roles_repo.get_user_role_ids(&tenant_id.0, body.user_id).await?;
        let group_names  = groups_repo.get_user_group_role_uids(&tenant_id.0, body.user_id).await?;
        let group_ids    = groups_repo.get_user_group_role_ids(&tenant_id.0, body.user_id).await?;

        let mut seen_names = std::collections::HashSet::new();
        let names: Vec<String> = direct_names.into_iter().chain(group_names)
            .filter(|n| seen_names.insert(n.clone()))
            .collect();
        let mut seen_ids = std::collections::HashSet::new();
        let ids: Vec<Uuid> = direct_ids.into_iter().chain(group_ids)
            .filter(|id| seen_ids.insert(*id))
            .collect();
        (names, ids)
    };

    tracing::debug!(
        tenant_id = %tenant_id.0,
        user_id = %body.user_id,
        roles = ?role_names,
        "resolved user roles"
    );

    let context = body.context.unwrap_or_else(|| serde_json::json!({}));
    let resource = body.resource.clone();

    // Load only the permissions attached to the user's roles.
    // Policies use "principals": ["*"] scoped by role-permission attachment —
    // a user with no matching role gets an empty PolicySet and is denied.
    let policy_set = state
        .permissions_service
        .get_policy_set_for_roles(&tenant_id.0, &role_ids)
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

    // All-actions check: fetch relevant (action, specific_resource) pairs then evaluate each.
    // Each action is evaluated against its own specific resource (e.g. table-level) rather than
    // the caller-supplied scope, because compiled policies use `resource ==` at the table level.
    let action_resources = state
        .packages_service
        .get_actions_for_resource(&resource)
        .await?;

    let mut decisions: HashMap<String, bool> = HashMap::new();
    {
        let schema = state.cedar_schema.read().unwrap();
        for (action, action_resource) in &action_resources {
            let allowed = is_allowed(&AuthzRequest {
                user_id: body.user_id,
                role_names: &role_names,
                action,
                resource: action_resource,
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