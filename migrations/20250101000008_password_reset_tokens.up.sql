-- Password reset tokens for forgot-password flow (token sent by email, then used in reset-password).
CREATE TABLE auth.password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL REFERENCES auth.tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_password_reset_tokens_token ON auth.password_reset_tokens(token);
CREATE INDEX idx_password_reset_tokens_expires ON auth.password_reset_tokens(expires_at);
