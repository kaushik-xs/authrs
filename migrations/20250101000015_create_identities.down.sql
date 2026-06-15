-- Reverse of Phase 1 additive schema.
DROP INDEX IF EXISTS idx_users_identity;
ALTER TABLE users DROP COLUMN IF EXISTS identity_id;

DROP TABLE IF EXISTS identity_oauth_accounts;

DROP INDEX IF EXISTS uq_identities_mobile;
DROP INDEX IF EXISTS uq_identities_email;
DROP TABLE IF EXISTS identities;
