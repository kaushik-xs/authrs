-- Users: identity rule = email OR (mobile AND country_code) OR username
CREATE TABLE auth.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL REFERENCES auth.tenants(id) ON DELETE CASCADE,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255),
    username VARCHAR(255),
    mobile VARCHAR(50),
    country_code VARCHAR(5),
    password_hash TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_identity_check CHECK (
        email IS NOT NULL OR
        (mobile IS NOT NULL AND country_code IS NOT NULL) OR
        username IS NOT NULL
    ),
    CONSTRAINT users_email_unique UNIQUE (tenant_id, email),
    CONSTRAINT users_username_unique UNIQUE (tenant_id, username),
    CONSTRAINT users_mobile_unique UNIQUE (tenant_id, mobile, country_code)
);

CREATE INDEX idx_users_tenant ON auth.users(tenant_id);
CREATE INDEX idx_users_tenant_email ON auth.users(tenant_id, email) WHERE email IS NOT NULL;
CREATE INDEX idx_users_tenant_username ON auth.users(tenant_id, username) WHERE username IS NOT NULL;
CREATE INDEX idx_users_tenant_mobile ON auth.users(tenant_id, mobile, country_code) WHERE mobile IS NOT NULL;
