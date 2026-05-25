DROP TABLE IF EXISTS _auth_package_actions;
DROP TABLE IF EXISTS _auth_packages;

ALTER TABLE permissions
    DROP CONSTRAINT IF EXISTS uq_permissions_tenant_name;
ALTER TABLE permissions
    DROP COLUMN IF EXISTS description,
    DROP COLUMN IF EXISTS document,
    DROP COLUMN IF EXISTS created_at,
    DROP COLUMN IF EXISTS updated_at;
