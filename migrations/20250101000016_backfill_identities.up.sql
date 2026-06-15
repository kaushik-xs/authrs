-- Phase 2 — backfill identities from existing users, populate users.identity_id.
--
-- PREREQUISITE: the Phase 0 audit (scripts/identity_conflict_audit.sql) must report ZERO
-- cross-tenant email/mobile conflicts before this runs. This migration collapses rows that
-- share a global handle into ONE identity; if two *different* humans share an email/mobile
-- they would be silently merged. Triage conflicts first.
--
-- Canonical-profile rule: most recently updated row wins. Password conflict rule: where a
-- collapsed handle had >1 distinct password hash, set force_password_change (force-reset).

-- A) One identity per distinct email. Most-recent row supplies profile + credential.
INSERT INTO identities (email, mobile, country_code, first_name, last_name,
                        password_hash, mfa_enabled, failed_attempts, locked_until)
SELECT DISTINCT ON (lower(email))
       email, mobile, country_code, first_name, last_name,
       password_hash, mfa_enabled, failed_attempts, locked_until
FROM users
WHERE email IS NOT NULL
ORDER BY lower(email), updated_at DESC;

UPDATE users u
SET identity_id = i.id
FROM identities i
WHERE u.email IS NOT NULL
  AND i.email IS NOT NULL
  AND lower(i.email) = lower(u.email);

-- A.1) Force-reset where a collapsed email spanned >1 distinct password hash.
UPDATE identities i
SET force_password_change = true
FROM (
    SELECT lower(email) AS lemail
    FROM users
    WHERE email IS NOT NULL
    GROUP BY lower(email)
    HAVING count(DISTINCT password_hash) > 1
) c
WHERE i.email IS NOT NULL AND lower(i.email) = c.lemail;

-- B) One identity per distinct mobile among users that have NO email (mobile-only).
INSERT INTO identities (mobile, country_code, first_name, last_name,
                        password_hash, mfa_enabled, failed_attempts, locked_until)
SELECT DISTINCT ON (country_code, mobile)
       mobile, country_code, first_name, last_name,
       password_hash, mfa_enabled, failed_attempts, locked_until
FROM users
WHERE email IS NULL AND mobile IS NOT NULL
ORDER BY country_code, mobile, updated_at DESC;

UPDATE users u
SET identity_id = i.id
FROM identities i
WHERE u.identity_id IS NULL
  AND u.email IS NULL AND u.mobile IS NOT NULL
  AND i.email IS NULL AND i.mobile IS NOT NULL
  AND i.country_code = u.country_code AND i.mobile = u.mobile;

-- B.1) Force-reset where a collapsed mobile-only handle spanned >1 distinct password hash.
UPDATE identities i
SET force_password_change = true
FROM (
    SELECT country_code, mobile
    FROM users
    WHERE email IS NULL AND mobile IS NOT NULL
    GROUP BY country_code, mobile
    HAVING count(DISTINCT password_hash) > 1
) c
WHERE i.email IS NULL AND i.mobile = c.mobile
  AND i.country_code IS NOT DISTINCT FROM c.country_code;

-- C) Username-only users (no email, no mobile): one standalone LOCAL identity each
--    (1:1, never merged across tenants — there is no global handle to match on).
DO $$
DECLARE
    r RECORD;
    new_id UUID;
BEGIN
    FOR r IN
        SELECT id, first_name, last_name, password_hash, mfa_enabled, failed_attempts, locked_until
        FROM users
        WHERE identity_id IS NULL AND email IS NULL AND mobile IS NULL
    LOOP
        INSERT INTO identities (first_name, last_name, password_hash, mfa_enabled,
                                failed_attempts, locked_until)
        VALUES (r.first_name, r.last_name, r.password_hash, r.mfa_enabled,
                r.failed_attempts, r.locked_until)
        RETURNING id INTO new_id;

        UPDATE users SET identity_id = new_id WHERE id = r.id;
    END LOOP;
END $$;

-- Safety: every user row must now have an identity. Fail loudly otherwise.
DO $$
DECLARE orphans INT;
BEGIN
    SELECT count(*) INTO orphans FROM users WHERE identity_id IS NULL;
    IF orphans > 0 THEN
        RAISE EXCEPTION 'Backfill incomplete: % users have NULL identity_id', orphans;
    END IF;
END $$;
