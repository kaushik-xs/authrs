-- Tenant KV store: OAuth, password_policy, mfa_policy, etc.
-- When sensitive = true, value is encrypted at rest (application layer)
CREATE TABLE auth.kv_store (
    tenant_id VARCHAR(255) NOT NULL REFERENCES auth.tenants(id) ON DELETE CASCADE,
    group_key VARCHAR(255) NOT NULL,
    key VARCHAR(255) NOT NULL,
    value TEXT NOT NULL,
    sensitive BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, group_key, key)
);

CREATE INDEX idx_kv_store_tenant_group ON auth.kv_store(tenant_id, group_key);
