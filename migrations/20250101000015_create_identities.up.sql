-- Phase 1 of the shared-identity migration (docs/shared-identity-migration.md).
-- Additive only: create the global identity tables and add a nullable identity_id
-- to users. No FK/unique/NOT-NULL constraints yet — those land in Phase 3 after the
-- Phase 2 backfill. Fully reversible.

-- Global identity: "who you are" — login handles + credentials + canonical profile.
CREATE TABLE identities (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 VARCHAR(255),
    mobile                VARCHAR(50),
    country_code          VARCHAR(5),
    first_name            VARCHAR(255),
    last_name             VARCHAR(255),
    password_hash         TEXT,
    mfa_enabled           BOOLEAN NOT NULL DEFAULT false,
    mfa_secret            TEXT,
    force_password_change BOOLEAN NOT NULL DEFAULT false,
    failed_attempts       INT NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    status                VARCHAR(50) NOT NULL DEFAULT 'active',  -- global kill-switch
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- mobile and country_code are both-or-neither.
    CONSTRAINT identities_mobile_pair CHECK ((mobile IS NULL) = (country_code IS NULL))
    -- NOTE: no "email OR mobile required" check — username-only (handle-less) identities
    -- are valid. Loginability (email OR mobile OR a username membership) is enforced in
    -- the application layer.
);

-- GLOBAL uniqueness, case-insensitive email, NULLs allowed so many handle-less
-- identities can coexist. Created here (additive) — they only constrain identity rows,
-- which start empty; the users backfill in Phase 2 must respect them.
CREATE UNIQUE INDEX uq_identities_email  ON identities (lower(email))         WHERE email  IS NOT NULL;
CREATE UNIQUE INDEX uq_identities_mobile ON identities (country_code, mobile) WHERE mobile IS NOT NULL;

-- Social / federated login methods, linked to the GLOBAL identity (not a membership).
-- One identity may link multiple providers; a given provider account maps to exactly
-- one identity.
CREATE TABLE identity_oauth_accounts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id      UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    provider         VARCHAR(50)  NOT NULL,   -- 'google' | 'microsoft' | 'github'
    provider_user_id VARCHAR(255) NOT NULL,   -- the OIDC `sub`
    email            VARCHAR(255),            -- email as asserted by the provider
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_oauth_provider_subject UNIQUE (provider, provider_user_id)
);
CREATE INDEX idx_oauth_identity ON identity_oauth_accounts (identity_id);

-- Link column on the membership row. Nullable + no FK for now (Phase 3 adds FK,
-- UNIQUE(tenant_id, identity_id), and NOT NULL after the backfill populates it).
ALTER TABLE users ADD COLUMN identity_id UUID;
CREATE INDEX idx_users_identity ON users (identity_id);
