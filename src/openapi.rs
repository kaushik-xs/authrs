//! OpenAPI (Swagger) spec generation and /spec endpoint.
//! Spec includes servers, security, parameters, and request bodies so it is executable (e.g. Try it out in Swagger UI).

use utoipa::openapi::{
    content::Content,
    info::InfoBuilder,
    path::{
        HttpMethod, OperationBuilder, Parameter, ParameterBuilder, ParameterIn, PathItem, PathsBuilder,
    },
    request_body::RequestBodyBuilder,
    schema::{ComponentsBuilder, ObjectBuilder, Schema, SchemaType, Type},
    security::{
        ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme,
    },
    server::{ServerBuilder, ServerVariableBuilder},
    OpenApiBuilder,
};
use utoipa::openapi::{request_body::RequestBody, Required};

fn tenant_id_param() -> Parameter {
    ParameterBuilder::new()
        .name("X-Tenant-ID")
        .parameter_in(ParameterIn::Header)
        .required(Required::True)
        .description(Some("Tenant identifier (lower snake_case, e.g. my_tenant)"))
        .schema(Some(Schema::from(
            ObjectBuilder::new().schema_type(SchemaType::new(Type::String)),
        )))
        .build()
}

fn path_param(name: &str, description: &str) -> Parameter {
    ParameterBuilder::new()
        .name(name)
        .parameter_in(ParameterIn::Path)
        .required(Required::True)
        .description(Some(description.to_string()))
        .schema(Some(Schema::from(
            ObjectBuilder::new().schema_type(SchemaType::new(Type::String)),
        )))
        .build()
}

fn json_body(schema: ObjectBuilder) -> Option<RequestBody> {
    Some(
        RequestBodyBuilder::new()
            .content(
                "application/json",
                Content::new(Some(Schema::from(schema.build()))),
            )
            .required(Some(Required::True))
            .build(),
    )
}

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
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("firstName", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("lastName", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("email", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("mobile", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("countryCode", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("password", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("retypePassword", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("firstName")
                            .required("lastName")
                            .required("email")
                            .required("password")
                            .required("retypePassword"),
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
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("email", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("email"),
                    ))
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
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("token", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("newPassword", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("retypePassword", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("token")
                            .required("newPassword")
                            .required("retypePassword"),
                    ))
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
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("email", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("password", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("email")
                            .required("password"),
                    ))
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
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("username", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("password", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("username")
                            .required("password"),
                    ))
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
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("email", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("email"),
                    ))
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("identifier", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("code", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("channel", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("identifier")
                            .required("code")
                            .required("channel"),
                    ))
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
                    .description(Some("Initiates OAuth flow for the given provider (e.g. google, microsoft)."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("provider", "OAuth provider: google, microsoft"))
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
                    .parameter(path_param("provider", "OAuth provider"))
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("currentPassword", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("newPassword", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("retypePassword", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("currentPassword")
                            .required("newPassword")
                            .required("retypePassword"),
                    ))
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
                    .parameter(path_param("user_id", "User UUID"))
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
                    .parameter(tenant_id_param())
                    .parameter(path_param("user_id", "User UUID"))
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("roleId", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("roleId"),
                    ))
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
                    .parameter(tenant_id_param())
                    .parameter(path_param("user_id", "User UUID"))
                    .parameter(path_param("role_id", "Role UUID"))
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
                    .parameter(tenant_id_param())
                    .parameter(path_param("user_id", "User UUID"))
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("newPassword", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("retypePassword", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("newPassword")
                            .required("retypePassword"),
                    ))
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
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
                    .parameter(tenant_id_param())
                    .parameter(path_param("group_key", "KV group key"))
                    .parameter(path_param("key", "KV key"))
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
                    .parameter(tenant_id_param())
                    .parameter(path_param("group_key", "KV group key"))
                    .parameter(path_param("key", "KV key"))
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("value", ObjectBuilder::new().schema_type(SchemaType::new(Type::String))),
                    ))
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
                    .parameter(tenant_id_param())
                    .parameter(path_param("group_key", "KV group key"))
                    .parameter(path_param("key", "KV key"))
                    .build(),
            ),
        )
        .build();

    let components = ComponentsBuilder::new()
        .security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some(
                        "Session token sent as Authorization: Bearer {sessionToken}. \
                         To obtain a token: 1) Set X-Tenant-ID (tenant_id below). \
                         2) Call POST /login/email-password with body {\"email\", \"password\"}. \
                         3) Copy sessionToken from the response and paste it here.",
                    ))
                    .build(),
            ),
        )
        .security_scheme(
            "tenant_id",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-Tenant-ID",
                "Tenant identifier (lower snake_case, e.g. my_tenant). Required for tenant-scoped endpoints.",
            ))),
        )
        .build();

    OpenApiBuilder::new()
        .info(
            InfoBuilder::new()
                .title("Authrs API")
                .version(env!("CARGO_PKG_VERSION"))
                .description(Some("Multi-tenant authentication service. Use X-Tenant-ID header for tenant context; use Authorization: Bearer <sessionToken> for authenticated endpoints. Try it out: set server URL, authorize with tenant_id and/or bearer, then execute requests."))
                .build(),
        )
        .servers(Some([ServerBuilder::new()
            .url("http://{host}:{port}")
            .parameter(
                "host",
                ServerVariableBuilder::new()
                    .default_value("localhost")
                    .description(Some("API host (e.g. localhost or your deployment host)")),
            )
            .parameter(
                "port",
                ServerVariableBuilder::new()
                    .default_value("3000")
                    .description(Some("API port")),
            )
            .build()]))
        .paths(paths)
        .components(Some(components))
        .security(Some([SecurityRequirement::new("tenant_id", Vec::<String>::new())
            .add("bearer", Vec::<String>::new())]))
        .build()
}
