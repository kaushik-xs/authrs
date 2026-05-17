-- Tenants: id is lower snake_case string (e.g. my_tenant, acme_corp)
CREATE TABLE tenants (
    id VARCHAR(255) PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9_]*$'),
    name VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tenants_name ON tenants(name);
CREATE INDEX idx_tenants_status ON tenants(status);
