//! Tenant resolution from X-Tenant-ID header (lower snake_case string).

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

/// Lower snake_case: starts with lowercase letter, then [a-z0-9_]*.
fn is_lower_snake_case(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[derive(Clone, Debug)]
pub struct TenantId(pub String);

#[async_trait]
impl<S> FromRequestParts<S> for TenantId
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get("X-Tenant-ID")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::BAD_REQUEST, "Missing X-Tenant-ID header"))?
            .trim();
        if value.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "X-Tenant-ID must be non-empty"));
        }
        if !is_lower_snake_case(value) {
            return Err((
                StatusCode::BAD_REQUEST,
                "X-Tenant-ID must be lower snake_case (e.g. my_tenant)",
            ));
        }
        Ok(TenantId(value.to_string()))
    }
}
