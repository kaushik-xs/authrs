-- Add payload column for Postgres session store (when Redis disabled)
ALTER TABLE auth.sessions ADD COLUMN IF NOT EXISTS payload JSONB;
