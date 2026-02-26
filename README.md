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

2. Build and push using your Docker Hub username and optional tag:

   ```bash
   ./scripts/docker-build-push.sh YOUR_DOCKERHUB_USERNAME/authrs
   # or with a version tag:
   ./scripts/docker-build-push.sh YOUR_DOCKERHUB_USERNAME/authrs:v0.1.0
   ```

   Or set the image via env and run:

   ```bash
   DOCKER_IMAGE=YOUR_DOCKERHUB_USERNAME/authrs ./scripts/docker-build-push.sh
   ```

   The script builds the image from the repo root and pushes it to the registry. Use the same image name (e.g. `username/authrs`) to keep your public image updated.

## API overview

All tenant-scoped requests require the **X-Tenant-ID** header: a **lower snake_case** string (e.g. `my_tenant`, `acme_corp`).

- **Health**: `GET /health`, `GET /metrics`
- **Auth**: `POST /signup`, `POST /login/email-password`, `POST /login/username-password`, `POST /login/email-otp/request`, `POST /login/mobile-otp/request`, `POST /login/mobile-whatsapp-otp/request`, `POST /login/otp/verify`, `GET /oauth/:provider`, `GET /oauth/:provider/callback`
- **MFA**: `POST /mfa/enable`, `POST /mfa/verify`, `POST /mfa/validate`
- **Session**: `GET /session/validate`, `POST /session/logout`, `POST /session/logout/all`
- **Admin**: `POST /admin/users`, `GET /admin/users`, `POST /admin/groups`, …; `GET/PUT/DELETE /admin/kv_store/:group_key/:key`

See **postman/Authrs-API.postman_collection.json** for a full Postman collection. Set variables: `base_url`, `tenant_id`, `session_token` (after login).

## Configuration

| Env | Description |
|-----|-------------|
| `DATABASE_URL` | PostgreSQL connection string (required). Use `?options=-c%20search_path%3Dpublic%2Cauth` so tables live in the `auth` schema. |
| `REDIS_URL` | Redis URL (optional) |
| `REDIS_ENABLED` | Set to `false` to disable Redis even if URL is set |
| `SERVER_HOST`, `SERVER_PORT` | Bind address (default `0.0.0.0:3000`) |
| `RUST_LOG` | Log level (default `info`) |
| `KV_STORE_ENCRYPTION_KEY` | Base64 32-byte key for encrypting sensitive kv_store values |

## Project layout

- `src/api` – extractors (tenant), app state
- `src/domain` – user, tenant, session, RBAC types
- `src/routes` – auth, mfa, session, admin, health
- `src/services` – auth, otp, session, mfa, oauth, rbac, tenant_config
- `src/repo` – users, tenants, kv_store, sessions (Redis + Postgres), groups, roles, permissions, otp, mfa
- `src/middleware` – tenant resolution, auth, rbac, rate_limit
- `migrations/` – sqlx migrations
