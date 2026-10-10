-- Pending OAuth/OIDC authorization requests. Created by GET /oauth/:provider and consumed
-- (single-use) by GET /oauth/:provider/callback. Binds the provider round-trip to the
-- tenant that started it and carries the PKCE verifier + OIDC nonce.
CREATE TABLE oauth_states (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    state         VARCHAR(255) NOT NULL UNIQUE,
    tenant_id     VARCHAR(255) NOT NULL,
    provider      VARCHAR(50)  NOT NULL,
    pkce_verifier VARCHAR(255) NOT NULL,
    nonce         VARCHAR(255) NOT NULL,
    expires_at    TIMESTAMPTZ  NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_oauth_states_expires ON oauth_states(expires_at);
