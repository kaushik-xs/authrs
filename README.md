# authrs

Multi-tenant authentication service (Rust): email/username password, email/mobile OTP, OAuth (Google/Microsoft), MFA (TOTP + backup codes), RBAC, Redis-optional sessions, tenant KV store.

## Requirements

- Rust 1.70+
- PostgreSQL
- Redis (optional; if unset, sessions and rate limits use DB or in-memory fallback)

## Setup

1. Copy env example and set at least `DATABASE_URL`:

   ```bash
   cp .env.example .env
   # Edit .env: DATABASE_URL=postgres://user:pass@localhost:5432/authrs?options=-c%20search_path%3Dpublic%2Cauth
   ```

2. Create the database and run migrations:

   ```bash
   createdb authrs   # or your DB tool
   cargo install sqlx-cli --no-default-features --features postgres
   sqlx migrate run
   ```

3. (Optional) Set `REDIS_URL` for Redis-backed sessions and rate limiting. If omitted, sessions use PostgreSQL and rate limits use in-memory store.

4. Run the service:

   ```bash
   cargo run
   ```

   By default it listens on `http://0.0.0.0:3000`.

5. (Optional) Seed a tenant and admin user. **Use the `seed` binary**, not the server:

   ```bash
   export SEED_TENANT_ID=test
   export SEED_TENANT_NAME=Test
   export SEED_ADMIN_EMAIL=admin@example.com
   export SEED_ADMIN_PASSWORD=your-secret-password
   export SEED_ROLE_NAME=Owner
   cargo run --bin seed
   ```

   `DATABASE_URL` must be set (e.g. from `.env`). If `SEED_TENANT_ID` is not set, the seed binary exits without error (no-op). Do **not** use `cargo run --bin authrs -- seed` — that runs the server and ignores `seed`.

## Docker Compose

Runs the app and Redis only; the app connects to **PostgreSQL on your host** (no db container):

```bash
cp .env.docker.example .env
# Set DATABASE_URL to your host DB, e.g. postgres://user:pass@host.docker.internal:5432/authrs?options=-c%20search_path%3Dpublic%2Cauth
docker compose up -d
```

On Linux, uncomment the `extra_hosts` block for the app in `docker-compose.yml` so `host.docker.internal` resolves. Migrations run at app startup.

## Publishing to Docker Hub (public image)

1. Log in to Docker Hub (one-time):

   ```bash
   docker login
   ```

2. (One-time) Create a buildx builder so multi-platform builds work (needed for both amd64 servers and ARM Macs):

   ```bash
   docker buildx create --use
   ```

3. Build and push using your Docker Hub username and optional tag. The script builds for **linux/amd64** and **linux/arm64** so the same image runs on x86_64 (e.g. Ubuntu) and Apple Silicon:

   ```bash
   ./scripts/docker-build-push.sh YOUR_DOCKERHUB_USERNAME/authrs
   # or with a version tag:
   ./scripts/docker-build-push.sh YOUR_DOCKERHUB_USERNAME/authrs:v0.1.0
   ```

   Or set the image via env and run:

   ```bash
   DOCKER_IMAGE=YOUR_DOCKERHUB_USERNAME/authrs ./scripts/docker-build-push.sh
   ```

   Use the same image name (e.g. `username/authrs`) to keep your public image updated.

## API overview

All tenant-scoped requests require the **X-Tenant-ID** header: a **lower snake_case** string (e.g. `my_tenant`, `acme_corp`).

- **Health**: `GET /health`, `GET /metrics`
- **Auth**: `POST /signup`, `POST /login/email-password`, `POST /login/username-password`, `POST /login/email-otp/request`, `POST /login/mobile-otp/request`, `POST /login/mobile-whatsapp-otp/request`, `POST /login/otp/verify`, `GET /oauth/:provider`, `GET /oauth/:provider/callback`
- **MFA (authenticator app / TOTP)**: `GET /mfa/status`, `POST /mfa/enable`, `POST /mfa/verify`, `POST /mfa/validate`, `POST /mfa/disable`, `POST /mfa/backup-codes`
- **Session**: `GET /session/validate`, `POST /session/logout`, `POST /session/logout/all`
- **Admin**: `POST /admin/users`, `GET /admin/users`, `POST /admin/groups`, …; `GET/PUT/DELETE /admin/kv_store/:group_key/:key`

See **postman/Authrs-API.postman_collection.json** for a full Postman collection. Set variables: `base_url`, `tenant_id`, `session_token` (after login).

## OAuth (Google / Microsoft)

Providers are configured per tenant in the kv_store (group `oauth`, key `google` or `microsoft`; mark it `sensitive` so the secret is encrypted):

```json
{
  "clientId": "…",
  "clientSecret": "…",
  "redirectUrl": "https://app.example.com/oauth/callback/microsoft",
  "tenant": "organizations",
  "allowSignup": true
}
```

- `redirectUrl` is a **frontend** page registered with the provider (Google Cloud console / Entra app registration).
- `tenant` (Microsoft only): `common` (default), `organizations`, `consumers`, or an Entra tenant ID (GUID) to allow a single organization.
- `allowSignup` (default `true`): when `false`, only users who already have a membership in the tenant can sign in.

Flow:

1. `GET /oauth/:provider` with `X-Tenant-ID` → `{ authorizationUrl, state }`. Keep `state`, then navigate to `authorizationUrl`.
2. The provider redirects to `redirectUrl?code=…&state=…`. Check `state` matches.
3. Frontend calls `GET /oauth/:provider/callback?code=…&state=…` → the standard login response (`sessionToken` / `mfaRequired` / `passwordChangeRequired`).

Account linking: a known provider account logs in as its identity; otherwise a provider-**verified** email links to the existing identity with that email; otherwise a new password-less identity is created. Microsoft emails count as verified only for personal accounts or when the `xms_edov` optional claim is enabled on the app registration. Tenants with an email-domain allowlist require a verified email.

## MFA (authenticator app)

TOTP per RFC 6238 (SHA-1, 6 digits, 30 s), compatible with Google/Microsoft Authenticator, Authy, 1Password, etc. MFA belongs to the global identity, so it applies in every tenant and to every login method (password, OTP, OAuth, SSO tenant selection). Secrets are encrypted with `KV_STORE_ENCRYPTION_KEY` (required for MFA).

Enrollment (Bearer session):

1. `POST /mfa/enable` → `{ secret, otpauthUrl }`. Show `otpauthUrl` as a QR code (and `secret` for manual entry).
2. `POST /mfa/verify` `{ code }` → `{ enabled: true, backupCodes }`. Show the 10 backup codes once.

Login: any login returning `{ mfaRequired: true, mfaToken }` is completed with `POST /mfa/validate` `{ mfaToken, code }` (a TOTP code or a backup code) → `{ sessionToken, expiresAt }`. The token lasts 5 minutes / 5 attempts; wrong codes also count toward the account lockout. TOTP codes cannot be replayed.

Management (Bearer session, current code required): `POST /mfa/disable`, `POST /mfa/backup-codes` (regenerate), `GET /mfa/status`.

## Configuration

| Env | Description |
|-----|-------------|
| `DATABASE_URL` | PostgreSQL connection string (required). Use `?options=-c%20search_path%3Dpublic%2Cauth` so tables live in the `auth` schema. |
| `REDIS_URL` | Redis URL (optional) |
| `REDIS_ENABLED` | Set to `false` to disable Redis even if URL is set |
| `SERVER_HOST`, `SERVER_PORT` | Bind address (default `0.0.0.0:3000`) |
| `RUST_LOG` | Log level (default `info`) |
| `KV_STORE_ENCRYPTION_KEY` | Base64 32-byte key for encrypting sensitive kv_store values and MFA secrets |
| `MFA_ISSUER` | Name shown in authenticator apps (default `Authrs`) |

## Project layout

- `src/api` – extractors (tenant), app state
- `src/domain` – user, tenant, session, RBAC types
- `src/routes` – auth, mfa, session, admin, health
- `src/services` – auth, otp, session, mfa, oauth, rbac, tenant_config
- `src/repo` – users, tenants, kv_store, sessions (Redis + Postgres), groups, roles, permissions, otp, mfa
- `src/middleware` – tenant resolution, auth, rbac, rate_limit
- `migrations/` – sqlx migrations

## Testing

```bash
cargo test                      # everything
cargo test --lib                # unit + component only (no database)
cargo test --test oauth_http    # one integration / end-to-end suite
```

The suites form a test pyramid. Most tests are fast and pure. Fewer tests run against a real database and the HTTP stack.

| Layer | Where | Needs | What it covers (OAuth) |
|-------|-------|-------|------------------------|
| Unit | `src/**` `#[cfg(test)]`, e.g. `src/services/oauth_tests.rs` | nothing | provider parsing, endpoint building, PKCE (RFC 7636 vector), claim normalization, Microsoft issuer / directory rules, callback-query validation |
| Component | `src/services/oauth_component_tests.rs` | nothing (in-process mock IdP) | code exchange, ID-token signature / alg / aud / iss / exp checks, JWKS caching, rotation and refetch throttling |
| Integration | `tests/oauth_repo.rs`, `tests/oauth_login.rs` | Postgres | single-use and expiring states (including concurrent redemption), account linking, auto-link by verified email only, signup policy, domain allowlist, login gates (status, lock, expiry, MFA, force-change) |
| End-to-end | `tests/oauth_http.rs` | Postgres | redirect → provider → callback → session through the real router, plus replay, forged and expired state, provider and tenant binding, nonce, PKCE, and error mapping |

Database tests use `#[sqlx::test]`. Each test gets a fresh database created from the server in `DATABASE_URL` (env or `.env`). Every migration is applied, and the database is dropped after the test passes, so the database user needs `CREATEDB`. Don't run two `cargo test` invocations against the same server at the same time: they race on test database names.

`tests/common/mock_idp.rs` is a mock OIDC provider (wiremock). It signs ID tokens with the **test-only** RSA keys in `tests/fixtures/`. The component tests and the end-to-end tests share it.
