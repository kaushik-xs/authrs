ALTER TABLE roles ADD COLUMN parent_role_id UUID REFERENCES roles(id) ON DELETE SET NULL;
CREATE INDEX idx_roles_parent_role_id ON roles(parent_role_id);
