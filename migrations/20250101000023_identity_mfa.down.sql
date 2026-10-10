DROP TABLE IF EXISTS mfa_challenges;
DROP TABLE IF EXISTS identity_backup_codes;
ALTER TABLE identities DROP COLUMN IF EXISTS mfa_last_used_step;
