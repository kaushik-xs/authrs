-- Phase 4 — repoint password_reset_tokens to the global identity. Password reset now
-- resets the one shared credential, so the token belongs to an identity, not a per-tenant
-- membership. Legacy user_id/tenant_id are kept (relaxed to nullable) for the rollback
-- window and dropped in Phase 6.

ALTER TABLE password_reset_tokens ADD COLUMN identity_id UUID;

-- Backfill from the membership populated in Phase 2.
UPDATE password_reset_tokens prt
SET identity_id = u.identity_id
FROM users u
WHERE u.id = prt.user_id;

ALTER TABLE password_reset_tokens ALTER COLUMN identity_id SET NOT NULL;
ALTER TABLE password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_identity_fk
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE;
CREATE INDEX idx_password_reset_tokens_identity ON password_reset_tokens(identity_id);

-- New global tokens only need identity_id; legacy anchors become optional.
ALTER TABLE password_reset_tokens ALTER COLUMN user_id   DROP NOT NULL;
ALTER TABLE password_reset_tokens ALTER COLUMN tenant_id DROP NOT NULL;
