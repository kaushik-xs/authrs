-- Phase 5d — short-lived identity tokens. Issued by tenant-less SSO login
-- (/login/identity) to prove the human authenticated; exchanged at /login/select-tenant
-- for a tenant-scoped session. Reusable until expiry so the user can pick among tenants.
CREATE TABLE identity_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    token       VARCHAR(255) NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_identity_tokens_token ON identity_tokens(token);
CREATE INDEX idx_identity_tokens_expires ON identity_tokens(expires_at);
