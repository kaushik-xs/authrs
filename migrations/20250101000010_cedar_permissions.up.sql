-- Evolve permissions table to store Cedar policy documents
ALTER TABLE permissions
    ADD COLUMN IF NOT EXISTS description TEXT,
    ADD COLUMN IF NOT EXISTS document    JSONB,
    ADD COLUMN IF NOT EXISTS created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Unique name per tenant
ALTER TABLE permissions
    DROP CONSTRAINT IF EXISTS uq_permissions_tenant_name;
ALTER TABLE permissions
    ADD CONSTRAINT uq_permissions_tenant_name UNIQUE (tenant_id, name);

-- Package table registry: one row per (package, table) combination
CREATE TABLE IF NOT EXISTS _auth_packages (
    package_id  VARCHAR(255) NOT NULL,
    table_name  VARCHAR(255) NOT NULL,
    PRIMARY KEY (package_id, table_name)
);

-- Custom actions per package
CREATE TABLE IF NOT EXISTS _auth_package_actions (
    package_id  VARCHAR(255) NOT NULL,
    action_name VARCHAR(255) NOT NULL,
    PRIMARY KEY (package_id, action_name)
);

CREATE INDEX IF NOT EXISTS idx_permissions_tenant ON permissions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_perm ON role_permissions(permission_id);
