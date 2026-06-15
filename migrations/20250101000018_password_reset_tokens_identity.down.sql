-- Reverse of Phase 4. Identity-only tokens (NULL user_id/tenant_id) created after the
-- redesign deployed cannot be represented in the legacy schema. They are ephemeral
-- password-reset tokens, so drop them on rollback before restoring the NOT NULL anchors.
DELETE FROM password_reset_tokens WHERE user_id IS NULL OR tenant_id IS NULL;
ALTER TABLE password_reset_tokens ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE password_reset_tokens ALTER COLUMN user_id   SET NOT NULL;

DROP INDEX IF EXISTS idx_password_reset_tokens_identity;
ALTER TABLE password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_identity_fk;
ALTER TABLE password_reset_tokens DROP COLUMN IF EXISTS identity_id;
