//! OpenAPI (Swagger) spec generation and /spec endpoint.

use utoipa::openapi::{
    info::InfoBuilder,
    path::{HttpMethod, OperationBuilder, PathItem, PathsBuilder},
    OpenApiBuilder,
};

/// Builds the OpenAPI 3 spec for the authrs service.
pub fn spec() -> utoipa::openapi::OpenApi {
    let paths = PathsBuilder::new()
        // Health & metrics
        .path(
            "/health",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("Health check"))
                    .description(Some("Returns OK if the service is running."))
                    .build(),
            ),
        )
        .path(
            "/metrics",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("Prometheus metrics"))
                    .description(Some("Returns metrics in Prometheus exposition format."))
                    .build(),
            ),
        )
        // Auth: signup & password
        .path(
            "/signup",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Register a new user"))
                    .description(Some(
                        "Requires X-Tenant-ID header. Body: firstName, lastName, email, mobile?, countryCode?, password, retypePassword.",
                    ))
                    .build(),
            ),
        )
        .path(
            "/forgot-password",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Request password reset"))
                    .description(Some("Requires X-Tenant-ID. Body: email. Sends reset link if email is registered."))
                    .build(),
            ),
        )
        .path(
            "/reset-password",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Reset password with token"))
                    .description(Some("Requires X-Tenant-ID. Body: token, newPassword, retypePassword."))
                    .build(),
            ),
        )
        // Login
        .path(
            "/login/email-password",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Login with email and password"))
                    .description(Some("Requires X-Tenant-ID. Body: email, password. Returns sessionToken or mfaRequired."))
                    .build(),
            ),
        )
        .path(
            "/login/username-password",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Login with username and password"))
                    .description(Some("Requires X-Tenant-ID. Body: username, password."))
                    .build(),
            ),
        )
        .path(
            "/login/email-otp/request",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Request email OTP"))
                    .description(Some("Requires X-Tenant-ID. Body: email. Sends 6-digit code via email."))
                    .build(),
            ),
        )
        .path(
            "/login/mobile-otp/request",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Request mobile OTP"))
                    .description(Some("Placeholder."))
                    .build(),
            ),
        )
        .path(
            "/login/mobile-whatsapp-otp/request",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Request WhatsApp OTP"))
                    .description(Some("Placeholder."))
                    .build(),
            ),
        )
        .path(
            "/login/otp/verify",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Verify OTP and complete login"))
                    .description(Some("Requires X-Tenant-ID. Body: identifier, code, channel (e.g. email)."))
                    .build(),
            ),
        )
        // OAuth
        .path(
            "/oauth/{provider}",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("OAuth redirect"))
                    .description(Some("Initiates OAuth flow for the given provider."))
                    .build(),
            ),
        )
        .path(
            "/oauth/{provider}/callback",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("OAuth callback"))
                    .description(Some("Callback URL for OAuth provider."))
                    .build(),
            ),
        )
        // MFA
        .path(
            "/mfa/enable",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Enable MFA"))
                    .description(Some("Requires Bearer token. Placeholder."))
                    .build(),
            ),
        )
        .path(
            "/mfa/verify",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Verify MFA"))
                    .description(Some("Placeholder."))
                    .build(),
            )
        )
        .path(
            "/mfa/validate",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Validate MFA"))
                    .description(Some("Placeholder."))
                    .build(),
            ),
        )
        // Session
        .path(
            "/session/validate",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("Validate session"))
                    .description(Some("Requires Authorization: Bearer <sessionToken>. Returns tenantId, userId, roles, permissions, expiresAt."))
                    .build(),
            ),
        )
        .path(
            "/session/me",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("Current user"))
                    .description(Some("Requires Bearer token. Returns session info and user profile."))
                    .build(),
            ),
        )
        .path(
            "/session/change-password",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Change password"))
                    .description(Some("Requires Bearer. Body: currentPassword, newPassword, retypePassword."))
                    .build(),
            ),
        )
        .path(
            "/session/logout",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Logout current session"))
                    .description(Some("Requires Bearer token."))
                    .build(),
            ),
        )
        .path(
            "/session/logout/all",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Logout all sessions for user"))
                    .description(Some("Requires Bearer and X-Tenant-ID."))
                    .build(),
            ),
        )
        // Admin
        .path(
            "/admin/users",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Create user (admin)"))
                    .description(Some("Requires admin. Placeholder."))
                    .build(),
            ),
        )
        .path(
            "/admin/users",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List users (admin)"))
                    .description(Some("Requires admin. Placeholder."))
                    .build(),
            ),
        )
        .path(
            "/admin/users/{user_id}/roles",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List user roles"))
                    .description(Some("Requires admin. Returns roles for the user."))
                    .build(),
            ),
        )
        .path(
            "/admin/users/{user_id}/roles",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Assign role to user"))
                    .description(Some("Requires admin. Body: roleId."))
                    .build(),
            ),
        )
        .path(
            "/admin/users/{user_id}/roles/{role_id}",
            PathItem::new(
                HttpMethod::Delete,
                OperationBuilder::new()
                    .summary(Some("Remove role from user"))
                    .description(Some("Requires admin."))
                    .build(),
            ),
        )
        .path(
            "/admin/users/{user_id}/reset-password",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Admin reset user password"))
                    .description(Some("Requires admin. Body: newPassword, retypePassword."))
                    .build(),
            ),
        )
        .path(
            "/admin/roles",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Create role"))
                    .description(Some("Requires admin. Placeholder."))
                    .build(),
            ),
        )
        .path(
            "/admin/roles",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List roles"))
                    .description(Some("Requires admin. Returns roles for tenant."))
                    .build(),
            ),
        )
        .path(
            "/admin/permissions",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Create permission"))
                    .description(Some("Requires admin. Placeholder."))
                    .build(),
            ),
        )
        .path(
            "/admin/permissions",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List permissions"))
                    .description(Some("Requires admin. Placeholder."))
                    .build(),
            ),
        )
        .path(
            "/admin/kv_store",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List KV store keys"))
                    .description(Some("Requires admin. Placeholder."))
                    .build(),
            ),
        )
        .path(
            "/admin/kv_store/{group_key}/{key}",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("Get KV value"))
                    .description(Some("Requires admin. Placeholder."))
                    .build(),
            ),
        )
        .path(
            "/admin/kv_store/{group_key}/{key}",
            PathItem::new(
                HttpMethod::Put,
                OperationBuilder::new()
                    .summary(Some("Set KV value"))
                    .description(Some("Requires admin. Placeholder."))
                    .build(),
            ),
        )
        .path(
            "/admin/kv_store/{group_key}/{key}",
            PathItem::new(
                HttpMethod::Delete,
                OperationBuilder::new()
                    .summary(Some("Delete KV value"))
                    .description(Some("Requires admin. Placeholder."))
                    .build(),
            ),
        )
        .build();

    OpenApiBuilder::new()
        .info(
            InfoBuilder::new()
                .title("Authrs API")
                .version(env!("CARGO_PKG_VERSION"))
                .description(Some("Multi-tenant authentication service. Use X-Tenant-ID header for tenant context; use Authorization: Bearer <sessionToken> for authenticated endpoints."))
                .build(),
        )
        .paths(paths)
        .build()
}
