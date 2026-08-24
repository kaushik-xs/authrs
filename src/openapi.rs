//! OpenAPI (Swagger) spec generation and /spec endpoint.
//! Spec includes servers, security, parameters, and request bodies so it is executable (e.g. Try it out in Swagger UI).

use utoipa::openapi::{
    content::Content,
    info::InfoBuilder,
    path::{
        HttpMethod, OperationBuilder, Parameter, ParameterBuilder, ParameterIn, PathItem, PathsBuilder,
    },
    request_body::RequestBodyBuilder,
    schema::{ArrayBuilder, ComponentsBuilder, ObjectBuilder, Schema, SchemaType, Type},
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

/// A plain string schema (the common request-body property shape).
fn s() -> ObjectBuilder {
    ObjectBuilder::new().schema_type(SchemaType::new(Type::String))
}

/// An array-of-strings schema.
fn s_arr() -> ArrayBuilder {
    ArrayBuilder::new().items(s())
}

fn query_param(name: &str, description: &str) -> Parameter {
    ParameterBuilder::new()
        .name(name)
        .parameter_in(ParameterIn::Query)
        .required(Required::False)
        .description(Some(description.to_string()))
        .schema(Some(Schema::from(
            ObjectBuilder::new().schema_type(SchemaType::new(Type::String)),
        )))
        .build()
}

fn int_query_param(name: &str, description: &str) -> Parameter {
    ParameterBuilder::new()
        .name(name)
        .parameter_in(ParameterIn::Query)
        .required(Required::False)
        .description(Some(description.to_string()))
        .schema(Some(Schema::from(
            ObjectBuilder::new().schema_type(SchemaType::new(Type::Integer)),
        )))
        .build()
}

/// The RSQL filter/sort/pagination query params shared by every list endpoint.
/// Applied via `add_list_params` so the four list operations stay consistent.
fn add_list_params(op: OperationBuilder) -> OperationBuilder {
    op.parameter(query_param(
        "q",
        "RSQL filter expression, e.g. status==active;createdAt=ge=2024-01-01T00:00:00Z. \
         Operators: == != =gt= =ge= =lt= =le= =in= =out= =like= =ilike= =contains= =starts= =ends= =between= =null=. \
         Combine with ; (AND) and , (OR); group with (). Filtering is rejected on unknown or sensitive fields (HTTP 422).",
    ))
    .parameter(query_param(
        "sort",
        "Comma-separated sort fields; prefix a field with - for descending, e.g. -createdAt,name.",
    ))
    .parameter(int_query_param("limit", "Max rows to return (default 50, max 1000)."))
    .parameter(int_query_param("offset", "Rows to skip for pagination (default 0)."))
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
///
/// Always includes at least core paths (/spec, /health, /metrics) so the returned spec is never
/// empty even when there are no entity-specific APIs.
pub fn spec() -> utoipa::openapi::OpenApi {
    let paths = PathsBuilder::new()
        // Self-describing: spec endpoint (always present so spec is never empty)
        .path(
            "/spec",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("OpenAPI spec"))
                    .description(Some("Returns this OpenAPI (Swagger) specification as JSON."))
                    .build(),
            ),
        )
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
                add_list_params(
                    OperationBuilder::new()
                        .summary(Some("List users (admin)"))
                        .description(Some(
                            "Requires admin. Supports RSQL filtering (q), sort, and limit/offset. \
                             Filterable fields: id, identityId, firstName, lastName, email, username, \
                             mobile, countryCode, status, mfaEnabled, accessValidUntil, createdAt, updatedAt. \
                             Also accepts includeArchived=true to include archived memberships.",
                        ))
                        .parameter(tenant_id_param())
                        .parameter(query_param(
                            "includeArchived",
                            "Set true to include archived memberships (default false).",
                        )),
                )
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
                add_list_params(
                    OperationBuilder::new()
                        .summary(Some("List roles"))
                        .description(Some(
                            "Requires admin. Returns roles for tenant. Supports RSQL filtering (q), \
                             sort, and limit/offset. Filterable fields: id, name, uid, parentRoleId.",
                        ))
                        .parameter(tenant_id_param()),
                )
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
                add_list_params(
                    OperationBuilder::new()
                        .summary(Some("List permissions"))
                        .description(Some(
                            "Requires admin. Supports RSQL filtering (q), sort, and limit/offset. \
                             Filterable fields: id, name, description.",
                        ))
                        .parameter(tenant_id_param()),
                )
                .build(),
            ),
        )
        // Groups
        .path(
            "/admin/users/{user_id}/groups",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List user groups"))
                    .description(Some("Requires admin. Returns groups the user is a member of."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("user_id", "User UUID"))
                    .build(),
            ),
        )
        .path(
            "/admin/groups",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Create group"))
                    .description(Some("Requires admin. Body: name, description?."))
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("name", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .property("description", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("name"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/admin/groups",
            PathItem::new(
                HttpMethod::Get,
                add_list_params(
                    OperationBuilder::new()
                        .summary(Some("List groups"))
                        .description(Some(
                            "Requires admin. Returns groups for tenant. Supports RSQL filtering (q), \
                             sort, and limit/offset. Filterable fields: id, name, uid, description.",
                        ))
                        .parameter(tenant_id_param()),
                )
                .build(),
            ),
        )
        .path(
            "/admin/groups/{group_id}",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("Get group"))
                    .description(Some("Requires admin. Returns group by id."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("group_id", "Group UUID"))
                    .build(),
            ),
        )
        .path(
            "/admin/groups/{group_id}",
            PathItem::new(
                HttpMethod::Delete,
                OperationBuilder::new()
                    .summary(Some("Delete group"))
                    .description(Some("Requires admin."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("group_id", "Group UUID"))
                    .build(),
            ),
        )
        .path(
            "/admin/groups/{group_id}/users",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Add user to group"))
                    .description(Some("Requires admin. Body: userId."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("group_id", "Group UUID"))
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("userId", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("userId"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/admin/groups/{group_id}/users",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List group members"))
                    .description(Some("Requires admin. Returns user IDs in the group."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("group_id", "Group UUID"))
                    .build(),
            ),
        )
        .path(
            "/admin/groups/{group_id}/users/{user_id}",
            PathItem::new(
                HttpMethod::Delete,
                OperationBuilder::new()
                    .summary(Some("Remove user from group"))
                    .description(Some("Requires admin."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("group_id", "Group UUID"))
                    .parameter(path_param("user_id", "User UUID"))
                    .build(),
            ),
        )
        .path(
            "/admin/groups/{group_id}/roles",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Assign role to group"))
                    .description(Some("Requires admin. Body: roleId."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("group_id", "Group UUID"))
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("roleId", ObjectBuilder::new().schema_type(SchemaType::new(Type::String)))
                            .required("roleId"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/admin/groups/{group_id}/roles",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List group roles"))
                    .description(Some("Requires admin. Returns roles assigned to the group."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("group_id", "Group UUID"))
                    .build(),
            ),
        )
        .path(
            "/admin/groups/{group_id}/roles/{role_id}",
            PathItem::new(
                HttpMethod::Delete,
                OperationBuilder::new()
                    .summary(Some("Remove role from group"))
                    .description(Some("Requires admin."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("group_id", "Group UUID"))
                    .parameter(path_param("role_id", "Role UUID"))
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
        // ── Auth: membership & SSO identity ───────────────────────────────────
        .path(
            "/signup/verify",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Accept a tenant membership invite"))
                    .description(Some("Redeems a verify-to-join email token to create the membership for an existing global identity. Body: token."))
                    .request_body(json_body(
                        ObjectBuilder::new().property("token", s()).required("token"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/login/identity",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Tenant-less SSO identity login"))
                    .description(Some("Authenticates an identity by email/password and returns a short-lived identity token plus the tenants it belongs to. Body: email, password."))
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("email", s())
                            .property("password", s())
                            .required("email")
                            .required("password"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/login/select-tenant",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Exchange identity token for a tenant session"))
                    .description(Some("Requires Authorization: Bearer <identityToken>. Mints a tenant-scoped session for the chosen tenant. Body: tenantId."))
                    .request_body(json_body(
                        ObjectBuilder::new().property("tenantId", s()).required("tenantId"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/identity/tenants",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List tenants for an identity token"))
                    .description(Some("Requires Authorization: Bearer <identityToken>. Returns the tenants the identity can select (the SSO tenant picker)."))
                    .build(),
            ),
        )
        .path(
            "/check-availability/email",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Check if an email is available"))
                    .description(Some("Requires X-Tenant-ID and a valid Bearer session. Returns whether the email is unused as a global identity handle across all tenants. Body: email."))
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new().property("email", s()).required("email"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/check-availability/username",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Check if a username is available"))
                    .description(Some("Requires X-Tenant-ID and a valid Bearer session. Returns whether the username is unused within the tenant. Body: username."))
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new().property("username", s()).required("username"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/check-availability/mobile",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Check if a mobile number is available"))
                    .description(Some("Requires X-Tenant-ID and a valid Bearer session. Returns whether the mobile+countryCode is unused as a global identity handle across all tenants. Body: mobile, countryCode."))
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("mobile", s())
                            .property("countryCode", s())
                            .required("mobile")
                            .required("countryCode"),
                    ))
                    .build(),
            ),
        )
        // ── Session: identity-wide operations ─────────────────────────────────
        .path(
            "/session/tenants",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List tenants for the current session"))
                    .description(Some("Requires Bearer session token. Returns the current tenant plus all tenants the session's identity belongs to (for a tenant switcher)."))
                    .build(),
            ),
        )
        .path(
            "/session/force-change-password",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Complete a forced password change"))
                    .description(Some("Authorized by the change token in the body (no Bearer). Sets a new password and returns a new session. Body: changeToken, newPassword, retypePassword."))
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("changeToken", s())
                            .property("newPassword", s())
                            .property("retypePassword", s())
                            .required("changeToken")
                            .required("newPassword")
                            .required("retypePassword"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/session/logout/global",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Global logout across all tenants"))
                    .description(Some("Requires Bearer session token. Revokes every session of the current identity across all of its tenant memberships."))
                    .build(),
            ),
        )
        .path(
            "/session/switch",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Switch to another tenant"))
                    .description(Some("Requires Bearer session token. Mints a new session for the target tenant using the current session's identity (no re-authentication). Body: tenantId."))
                    .request_body(json_body(
                        ObjectBuilder::new().property("tenantId", s()).required("tenantId"),
                    ))
                    .build(),
            ),
        )
        // ── Admin: user lifecycle ─────────────────────────────────────────────
        .path(
            "/admin/users/{user_id}/archive",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Archive a user"))
                    .description(Some("Requires admin. Marks the specified tenant user as archived."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("user_id", "User UUID"))
                    .build(),
            ),
        )
        .path(
            "/admin/users/{user_id}/access-validity",
            PathItem::new(
                HttpMethod::Patch,
                OperationBuilder::new()
                    .summary(Some("Set a user's access-validity expiry"))
                    .description(Some("Requires admin. Updates (or clears) the ISO-8601 timestamp until which the user's access remains valid. Body: accessValidUntil (null clears it)."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("user_id", "User UUID"))
                    .request_body(json_body(
                        ObjectBuilder::new().property("accessValidUntil", s()),
                    ))
                    .build(),
            ),
        )
        // ── Admin: role hierarchy & permissions ───────────────────────────────
        .path(
            "/admin/roles/{role_id}",
            PathItem::new(
                HttpMethod::Delete,
                OperationBuilder::new()
                    .summary(Some("Delete a role"))
                    .description(Some("Requires admin. Deletes the role, removes its permission links, and evicts cached permission state."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("role_id", "Role UUID"))
                    .build(),
            ),
        )
        .path(
            "/admin/roles/{role_id}/parent",
            PathItem::new(
                HttpMethod::Put,
                OperationBuilder::new()
                    .summary(Some("Set or clear a role's parent"))
                    .description(Some("Requires admin. Updates the role's parent in the hierarchy. Body: parentRoleId (null/omitted detaches the parent)."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("role_id", "Role UUID"))
                    .request_body(json_body(
                        ObjectBuilder::new().property("parentRoleId", s()),
                    ))
                    .build(),
            ),
        )
        .path(
            "/admin/roles/{role_id}/hierarchy",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("Get a role's ancestor hierarchy"))
                    .description(Some("Requires admin. Returns the ordered list of ancestor roles for the given role."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("role_id", "Role UUID"))
                    .build(),
            ),
        )
        .path(
            "/admin/roles/{role_id}/permissions",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Attach a permission to a role"))
                    .description(Some("Requires admin. Links an existing permission to the role and evicts cached permission state. Body: permissionId."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("role_id", "Role UUID"))
                    .request_body(json_body(
                        ObjectBuilder::new().property("permissionId", s()).required("permissionId"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/admin/roles/{role_id}/permissions",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List a role's permissions"))
                    .description(Some("Requires admin. Returns the permissions attached to the role (id, name, document)."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("role_id", "Role UUID"))
                    .build(),
            ),
        )
        .path(
            "/admin/roles/{role_id}/permissions/{permission_id}",
            PathItem::new(
                HttpMethod::Delete,
                OperationBuilder::new()
                    .summary(Some("Detach a permission from a role"))
                    .description(Some("Requires admin. Removes the permission-role link; 404 if the assignment does not exist."))
                    .parameter(path_param("role_id", "Role UUID"))
                    .parameter(path_param("permission_id", "Permission UUID"))
                    .build(),
            ),
        )
        // ── Admin: permission management & checks ──────────────────────────────
        .path(
            "/admin/permissions/check",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Evaluate a user's permission for a resource"))
                    .description(Some("Requires admin. Resolves the user's direct and group roles and runs the Cedar policy check. Body: userId, resource, action?, context?."))
                    .parameter(tenant_id_param())
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("userId", s())
                            .property("resource", s())
                            .property("action", s())
                            .property("context", ObjectBuilder::new().schema_type(SchemaType::new(Type::Object)))
                            .required("userId")
                            .required("resource"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/admin/permissions/{permission_id}",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("Get a permission"))
                    .description(Some("Requires admin. Returns the permission's name, description, and Cedar document; 404 if not found."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("permission_id", "Permission UUID"))
                    .build(),
            ),
        )
        .path(
            "/admin/permissions/{permission_id}",
            PathItem::new(
                HttpMethod::Delete,
                OperationBuilder::new()
                    .summary(Some("Delete a permission"))
                    .description(Some("Requires admin. Deletes the permission and evicts cached permission state; 404 if not found."))
                    .parameter(tenant_id_param())
                    .parameter(path_param("permission_id", "Permission UUID"))
                    .build(),
            ),
        )
        // ── Admin: package sync ────────────────────────────────────────────────
        .path(
            "/admin/packages/sync",
            PathItem::new(
                HttpMethod::Post,
                OperationBuilder::new()
                    .summary(Some("Sync a package's schema and actions"))
                    .description(Some("Registers a package's tables, extensible-field tables, and custom actions, then rebuilds the Cedar schema. Body: packageId, tables[], extensibleTables?[], customActions?[]."))
                    .request_body(json_body(
                        ObjectBuilder::new()
                            .property("packageId", s())
                            .property("tables", s_arr())
                            .property("extensibleTables", s_arr())
                            .property("customActions", s_arr())
                            .required("packageId")
                            .required("tables"),
                    ))
                    .build(),
            ),
        )
        .path(
            "/admin/packages/actions",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List packages with tables and actions"))
                    .description(Some("Returns every registered package grouped with its sorted tables and actions."))
                    .build(),
            ),
        )
        // ── Platform (builder-only) ────────────────────────────────────────────
        .path(
            "/tenants",
            PathItem::new(
                HttpMethod::Get,
                OperationBuilder::new()
                    .summary(Some("List all tenants (builder-only)"))
                    .description(Some("Requires a Bearer session in the builder tenant holding an allowed builder role. Returns all tenants."))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec must cover every registered route. This list mirrors `src/routes/*`;
    /// update both together. (Path templates use `{param}` form as emitted by utoipa.)
    const EXPECTED_PATHS: &[&str] = &[
        "/spec", "/health", "/metrics",
        "/signup", "/signup/verify", "/forgot-password", "/reset-password",
        "/login/email-password", "/login/username-password", "/login/email-otp/request",
        "/login/mobile-otp/request", "/login/mobile-whatsapp-otp/request", "/login/otp/verify",
        "/login/identity", "/login/select-tenant", "/identity/tenants",
        "/check-availability/email", "/check-availability/username", "/check-availability/mobile",
        "/oauth/{provider}", "/oauth/{provider}/callback",
        "/mfa/enable", "/mfa/verify", "/mfa/validate",
        "/session/validate", "/session/me", "/session/tenants", "/session/change-password",
        "/session/force-change-password", "/session/logout", "/session/logout/all",
        "/session/logout/global", "/session/switch",
        "/admin/users", "/admin/users/{user_id}/roles", "/admin/users/{user_id}/roles/{role_id}",
        "/admin/users/{user_id}/groups", "/admin/users/{user_id}/archive",
        "/admin/users/{user_id}/reset-password", "/admin/users/{user_id}/access-validity",
        "/admin/roles", "/admin/roles/{role_id}", "/admin/roles/{role_id}/parent",
        "/admin/roles/{role_id}/hierarchy", "/admin/roles/{role_id}/permissions",
        "/admin/roles/{role_id}/permissions/{permission_id}",
        "/admin/groups", "/admin/groups/{group_id}", "/admin/groups/{group_id}/users",
        "/admin/groups/{group_id}/users/{user_id}", "/admin/groups/{group_id}/roles",
        "/admin/groups/{group_id}/roles/{role_id}",
        "/admin/permissions", "/admin/permissions/check", "/admin/permissions/{permission_id}",
        "/admin/kv_store", "/admin/kv_store/{group_key}/{key}",
        "/admin/packages/sync", "/admin/packages/actions",
        "/tenants",
    ];

    #[test]
    fn spec_contains_all_registered_paths() {
        let spec = spec();
        for p in EXPECTED_PATHS {
            assert!(
                spec.paths.paths.contains_key(*p),
                "OpenAPI spec is missing path {p}"
            );
        }
    }

    #[test]
    fn spec_serializes_to_json() {
        // The /spec handler unwraps this, so a malformed schema would panic in production.
        let json = spec().to_pretty_json().expect("spec serializes");
        assert!(json.contains("\"/admin/users\""));
        assert!(json.contains("\"/admin/packages/sync\""));
    }

    #[test]
    fn list_endpoints_expose_rsql_params() {
        let spec = spec();
        for p in ["/admin/users", "/admin/roles", "/admin/permissions", "/admin/groups"] {
            let item = spec.paths.paths.get(p).expect("path present");
            let get = item
                .get
                .as_ref()
                .expect("list endpoint has a GET operation");
            let names: Vec<&str> = get
                .parameters
                .as_ref()
                .map(|ps| ps.iter().map(|p| p.name.as_str()).collect())
                .unwrap_or_default();
            for expected in ["q", "sort", "limit", "offset"] {
                assert!(
                    names.contains(&expected),
                    "GET {p} is missing the '{expected}' query param"
                );
            }
        }
    }
}
