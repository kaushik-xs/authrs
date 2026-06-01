DROP INDEX IF EXISTS idx_roles_parent_role_id;
ALTER TABLE roles DROP COLUMN IF EXISTS parent_role_id;
