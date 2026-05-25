//! Cedar authorization middleware.
//! Wrap a route with `require_permission(resource_path, action_override)` to enforce Cedar policies.

use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::api::state::AppState;
use crate::error::AppError;
use crate::policy::engine::{authorize, derive_action_name, AuthzRequest};

/// Axum middleware that enforces Cedar authorization for a route.
///
/// - `resource_path`: hierarchical path e.g. `"service:core/package:manufacturing_core/table:materials"`
/// - `action_override`: explicit action name e.g. `Some("approveBom")`;
///   if `None` the action is derived from the HTTP verb + table name in the resource path.
pub async fn require_permission(
    resource_path: &'static str,
    action_override: Option<&'static str>,
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    // 1. Extract Bearer token
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("Missing Bearer token".to_string()))?
        .to_string();

    // 2. Load session
    let session = state
        .session_store
        .get(&token)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Session not found or expired".to_string()))?;

    // 3. Resolve role UUIDs from session role names
    let role_ids: Vec<uuid::Uuid> = {
        let roles_repo = state.auth_service.roles_repo();
        let mut ids = Vec::new();
        for role_name in &session.roles {
            if let Some(id) = roles_repo
                .get_role_id_by_name(&session.tenant_id, role_name)
                .await?
            {
                ids.push(id);
            }
        }
        ids
    };

    // 4. Derive action name
    let http_method = req.method().as_str();
    let action = match action_override {
        Some(a) => a.to_string(),
        None => derive_action_name(http_method, resource_path).ok_or_else(|| {
            AppError::Internal(format!(
                "Cannot derive action from method={http_method} resource={resource_path}"
            ))
        })?,
    };

    // 5. Build Cedar context from session + request metadata
    let mfa_verified = session.permissions.contains(&"mfa_verified".to_string());
    let context = serde_json::json!({
        "tenant_id": session.tenant_id,
        "actor_type": "user",
        "mfa_verified": mfa_verified,
    });

    // 6. Load PolicySet (cached per tenant)
    let schema_guard = state.cedar_schema.read().unwrap();
    let policy_set = state
        .permissions_service
        .get_policy_set(&session.tenant_id, &schema_guard)
        .await?;

    // 7. Evaluate
    let decision = authorize(
        &AuthzRequest {
            user_id: session.user_id,
            role_ids: &role_ids,
            action: &action,
            resource: resource_path,
            context,
        },
        &policy_set,
        &schema_guard,
    );

    drop(schema_guard);

    match decision {
        cedar_policy::Decision::Allow => Ok(next.run(req).await),
        cedar_policy::Decision::Deny => Err(AppError::Forbidden(
            "Policy evaluation denied this request".to_string(),
        )),
    }
}
