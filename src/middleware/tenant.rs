//! Tenant resolution middleware: load tenant from DB, attach config from kv_store.

use axum::{
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use crate::api::state::AppState;
use crate::api::tenant::TenantId;
use crate::domain::tenant::Tenant;
use crate::error::AppError;
use crate::repo::tenants::TenantsRepo;
use crate::services::tenant_config::TenantConfigLoader;

/// State for tenant resolution (held inside AppState).
#[derive(Clone)]
pub struct TenantState {
    pub tenants_repo: TenantsRepo,
    pub tenant_config: TenantConfigLoader,
}

/// Extractor for resolved tenant (after middleware has run).
#[derive(Clone)]
pub struct ResolvedTenant {
    pub id: String,
    pub tenant: Tenant,
}

/// Middleware: require X-Tenant-ID, load tenant from DB, attach to request extensions.
pub async fn tenant_resolution_middleware(
    State(state): State<std::sync::Arc<AppState>>,
    tenant_id: TenantId,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let tenant = match state.tenant_state.tenants_repo.get_by_id(&tenant_id.0).await {
        Ok(Some(t)) => t,
        Ok(None) => return AppError::NotFound("Tenant not found".to_string()).into_response(),
        Err(e) => return e.into_response(),
    };
    if tenant.status != "active" {
        return AppError::Forbidden("Tenant is not active".to_string()).into_response();
    }
    let mut request = request;
    request.extensions_mut().insert(ResolvedTenant {
        id: tenant.id.clone(),
        tenant,
    });
    next.run(request).await
}
