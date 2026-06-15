-- Schema rollback for Phase 6. Re-creates the dropped columns (nullable / defaulted).
-- NOTE: the original column VALUES are not recoverable — this only restores structure.
ALTER TABLE users
    ADD COLUMN first_name VARCHAR(255),
    ADD COLUMN last_name VARCHAR(255),
    ADD COLUMN email VARCHAR(255),
    ADD COLUMN mobile VARCHAR(50),
    ADD COLUMN country_code VARCHAR(5),
    ADD COLUMN password_hash TEXT,
    ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN force_password_change BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN locked_until TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_tenant_mobile ON users(tenant_id, mobile, country_code) WHERE mobile IS NOT NULL;

ALTER TABLE password_reset_tokens
    ADD COLUMN tenant_id VARCHAR(255),
    ADD COLUMN user_id UUID;
