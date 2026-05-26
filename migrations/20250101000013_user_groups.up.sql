-- User groups: combine users for shared roles, Cedar group policies, and bulk operations.
CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    uid VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, uid)
);

CREATE INDEX idx_groups_tenant ON groups(tenant_id);

-- Group membership
CREATE TABLE user_groups (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX idx_user_groups_user  ON user_groups(user_id);
CREATE INDEX idx_user_groups_group ON user_groups(group_id);

-- Roles assigned to groups (users inherit these through membership)
CREATE TABLE group_roles (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id  UUID NOT NULL REFERENCES roles(id)  ON DELETE CASCADE,
    PRIMARY KEY (group_id, role_id)
);

CREATE INDEX idx_group_roles_group ON group_roles(group_id);
CREATE INDEX idx_group_roles_role  ON group_roles(role_id);
