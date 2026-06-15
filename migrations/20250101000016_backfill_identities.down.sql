-- Reverse of Phase 2 backfill. Must run after Phase 3 constraints are reverted
-- (sqlx reverts in reverse version order, so 17.down precedes 16.down).
UPDATE users SET identity_id = NULL;
DELETE FROM identities;  -- cascades to identity_oauth_accounts
