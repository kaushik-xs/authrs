-- Phase 0 — cross-tenant conflict audit (docs/shared-identity-migration.md §6).
-- READ-ONLY. Run BEFORE the Phase 2 backfill and BEFORE the Phase 3 global-unique
-- indexes. Same email/mobile across tenants may be the same human (safe to collapse to
-- one identity) or different humans on a shared mailbox (must NOT collapse).
--
-- Usage:
--   psql "$DATABASE_URL" -f scripts/identity_conflict_audit.sql

\echo '== 1. Emails appearing in more than one tenant (case-insensitive) =='
SELECT lower(email)                  AS email,
       count(DISTINCT tenant_id)     AS tenant_count,
       count(*)                      AS row_count,
       count(DISTINCT password_hash) AS distinct_password_hashes,  -- >1 => force-reset
       array_agg(DISTINCT tenant_id) AS tenants
FROM users
WHERE email IS NOT NULL
GROUP BY lower(email)
HAVING count(DISTINCT tenant_id) > 1
ORDER BY tenant_count DESC, email;

\echo '== 2. Mobiles (country_code + number) appearing in more than one tenant =='
SELECT country_code,
       mobile,
       count(DISTINCT tenant_id)     AS tenant_count,
       count(*)                      AS row_count,
       array_agg(DISTINCT tenant_id) AS tenants
FROM users
WHERE mobile IS NOT NULL
GROUP BY country_code, mobile
HAVING count(DISTINCT tenant_id) > 1
ORDER BY tenant_count DESC;

\echo '== 3. Summary counts =='
SELECT
  (SELECT count(*) FROM (
     SELECT 1 FROM users WHERE email IS NOT NULL
     GROUP BY lower(email) HAVING count(DISTINCT tenant_id) > 1) e)  AS conflicting_emails,
  (SELECT count(*) FROM (
     SELECT 1 FROM users WHERE mobile IS NOT NULL
     GROUP BY country_code, mobile HAVING count(DISTINCT tenant_id) > 1) m) AS conflicting_mobiles,
  (SELECT count(DISTINCT lower(email)) FROM users WHERE email IS NOT NULL)  AS distinct_emails,
  (SELECT count(*) FROM users)                                              AS total_user_rows,
  (SELECT count(*) FROM users
     WHERE email IS NULL AND mobile IS NULL AND username IS NOT NULL)       AS username_only_rows;
