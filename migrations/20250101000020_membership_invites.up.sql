-- Phase 5e — membership invites. When public signup collides with an existing GLOBAL
-- identity, we don't silently attach; instead we email the identity owner a verify link.
-- Accepting the invite creates the membership in the target tenant. The credential is NOT
-- stored here (it already lives on the identity).
CREATE TABLE membership_invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    tenant_id   VARCHAR(255) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    first_name  VARCHAR(255),
    last_name   VARCHAR(255),
    username    VARCHAR(255),
    token       VARCHAR(255) NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_membership_invites_token ON membership_invites(token);
CREATE INDEX idx_membership_invites_expires ON membership_invites(expires_at);
