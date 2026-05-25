ALTER TABLE roles ADD COLUMN IF NOT EXISTS uid VARCHAR(255);

-- Backfill existing rows: lowercase, non-alphanumeric runs → '_', strip leading/trailing '_'
UPDATE roles
SET uid = TRIM('_' FROM REGEXP_REPLACE(LOWER(TRIM(name)), '[^a-z0-9]+', '_', 'g'))
WHERE uid IS NULL;

ALTER TABLE roles ALTER COLUMN uid SET NOT NULL;

ALTER TABLE roles ADD CONSTRAINT uq_roles_tenant_uid UNIQUE (tenant_id, uid);
