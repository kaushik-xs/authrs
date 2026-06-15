-- Reverse of Phase 3 constraints. Restores the per-tenant uniqueness + identity rule on
-- users and removes the identity linkage constraints (the column itself is removed by the
-- Phase 1 down migration).
ALTER TABLE users
    ADD CONSTRAINT users_identity_check CHECK (
        email IS NOT NULL OR
        (mobile IS NOT NULL AND country_code IS NOT NULL) OR
        username IS NOT NULL
    );
ALTER TABLE users ADD CONSTRAINT users_mobile_unique UNIQUE (tenant_id, mobile, country_code);
ALTER TABLE users ADD CONSTRAINT users_email_unique  UNIQUE (tenant_id, email);

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_identity_unique;
ALTER TABLE users ALTER COLUMN identity_id DROP NOT NULL;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_identity_fk;
