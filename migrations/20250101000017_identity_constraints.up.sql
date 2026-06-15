-- Phase 3 — constrain the membership row now that the Phase 2 backfill populated
-- users.identity_id. Credential/handle columns on users are KEPT until Phase 6 (rollback
-- window); only their now-redundant constraints are dropped here.

-- Link to the global identity, and require it.
ALTER TABLE users
    ADD CONSTRAINT users_identity_fk
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE;

ALTER TABLE users ALTER COLUMN identity_id SET NOT NULL;

-- One membership per identity per tenant.
ALTER TABLE users
    ADD CONSTRAINT users_tenant_identity_unique UNIQUE (tenant_id, identity_id);

-- The per-tenant email/mobile uniqueness and the email|mobile|username identity rule now
-- live on identities (global). Drop them from users. Username uniqueness stays per-tenant.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_unique;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_mobile_unique;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_identity_check;
