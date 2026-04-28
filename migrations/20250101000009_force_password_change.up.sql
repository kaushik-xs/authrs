ALTER TABLE auth.users ADD COLUMN force_password_change BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE auth.force_change_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL REFERENCES auth.tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_force_change_tokens_token ON auth.force_change_tokens(token);
CREATE INDEX idx_force_change_tokens_expires ON auth.force_change_tokens(expires_at);
