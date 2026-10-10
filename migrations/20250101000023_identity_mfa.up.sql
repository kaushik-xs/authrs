-- TOTP MFA on the GLOBAL identity (identities.mfa_enabled / mfa_secret already exist).
-- The older per-membership tables (user_mfa_secrets, user_backup_codes) are unused.

-- Last accepted TOTP time step: a code cannot be replayed within its validity window.
ALTER TABLE identities ADD COLUMN mfa_last_used_step BIGINT;

-- Single-use recovery codes (SHA-256 of the normalized code; codes are high-entropy random).
CREATE TABLE identity_backup_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    code_hash   VARCHAR(64) NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_identity_backup_codes_identity ON identity_backup_codes(identity_id);

-- Pending second-factor challenges: issued when a login passes the first factor for an
-- identity with MFA enabled; redeemed at POST /mfa/validate for a tenant session.
CREATE TABLE mfa_challenges (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token         VARCHAR(255) NOT NULL UNIQUE,
    tenant_id     VARCHAR(255) NOT NULL,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attempt_count INT NOT NULL DEFAULT 0,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mfa_challenges_expires ON mfa_challenges(expires_at);
