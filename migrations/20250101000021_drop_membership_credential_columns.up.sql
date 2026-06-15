-- Phase 6 (one-way cleanup). The credential + handle/profile columns on `users` and the
-- legacy anchors on `password_reset_tokens` are now fully owned by `identities`. Code reads
-- display fields by joining identities and credentials from identities directly, so these
-- columns are dead and safe to drop.
--
-- IRREVERSIBLE in data terms: the down migration re-creates the columns (schema rollback)
-- but cannot restore the dropped values. Run only after a stable release + verified backup.

-- Dropping email/mobile/country_code also drops their partial indexes
-- (idx_users_tenant_email, idx_users_tenant_mobile) automatically.
ALTER TABLE users
    DROP COLUMN IF EXISTS first_name,
    DROP COLUMN IF EXISTS last_name,
    DROP COLUMN IF EXISTS email,
    DROP COLUMN IF EXISTS mobile,
    DROP COLUMN IF EXISTS country_code,
    DROP COLUMN IF EXISTS password_hash,
    DROP COLUMN IF EXISTS mfa_enabled,
    DROP COLUMN IF EXISTS force_password_change,
    DROP COLUMN IF EXISTS failed_attempts,
    DROP COLUMN IF EXISTS locked_until;

-- Password reset is global (identity_id); the per-tenant/user anchors are no longer used.
ALTER TABLE password_reset_tokens
    DROP COLUMN IF EXISTS user_id,
    DROP COLUMN IF EXISTS tenant_id;
