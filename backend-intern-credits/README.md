# backend-intern-credits

LawVriksh Backend Intern Assignment 2 — Credit Management API & Schema.

## Quick Start

Run these commands from the repository root:

```bash
cd backend-intern-credits
python -m venv .venv
source .venv/bin/activate
pip install -r src/requirements.txt
cp .env.example .env
# Configure DATABASE_URL and two different strong keys (32+ random characters):
# ADMIN_API_KEY and CREDIT_ADMIN_API_KEY; also set exact frontend CORS_ORIGINS.
set -a && source .env && set +a
psql "${DATABASE_URL/+psycopg/}" -v ON_ERROR_STOP=1 -f schema.sql
uvicorn src.main:app --reload
```

Applying `schema.sql` is idempotent and upgrades existing databases with the password hash, revocable sessions, and database-backed sign-in throttling table. Back up any important database before applying schema changes. Legacy users created before authentication was introduced have no password hash and cannot sign in until an administrator provisions credentials through a trusted, out-of-band process.

To run the daily scheduler in the same process:

```bash
uvicorn src.app_with_scheduler:app --reload
```

The scheduler runs at 00:00 UTC, ensures existing users have credit rows, and adds 5 credits to each balance. A `credit_daily_runs` ledger and a unique UTC date key make this operation idempotent when a job retries or multiple worker processes attempt the same daily run. Test scheduled changes against an isolated database before enabling a production schedule.

## Authentication and account ownership

- `POST /api/auth/register` creates a new account with a zero-credit balance. Passwords must be 12–128 characters and are stored as salted PBKDF2-HMAC-SHA256 hashes. Registration requests are throttled by a one-way fingerprint of a registration marker and the direct client address: after 10 attempts in a 15-minute window, further attempts from that client are blocked for 15 minutes (HTTP 429 with `Retry-After: 900`). This is a per-client limit, so shared networks may share that registration quota.
- `POST /api/auth/login` returns an opaque bearer token. Only its SHA-256 hash is stored in PostgreSQL. Failed attempts are counted using a one-way fingerprint of the normalized email and direct client address, without storing either value in the attempt table. After 10 failed attempts for that pair within a 15-minute window, sign-in is blocked for 15 minutes and returns HTTP 429 with `Retry-After: 900`.
- `GET /api/auth/me` returns the signed-in account.
- `POST /api/auth/logout` revokes the current session.
- Failed sign-in attempts are throttled for 15 minutes after 10 failures per email/client fingerprint. Only a one-way hash is stored; the daily maintenance run expires old throttle records.
- Balance reads require `Authorization: Bearer <token>`. A normal account can read only its own balance; a trusted operator may read another account when the request also includes the valid `X-API-Key`.
- All add, deduct, and reset operations require a valid bearer session and the separate `CREDIT_ADMIN_API_KEY` in `X-API-Key`. A signed-in user cannot mint credits into their own account without operator authorization. A credit operator may access another account with the same credit key; ordinary requests return a not-found response rather than revealing that account.
- Schema migration endpoints use a distinct `ADMIN_API_KEY`. Keep the schema-admin secret separate from the credit-operator secret and grant the schema credential to fewer people.
- Sessions expire after eight hours. Password reset, email verification, and legacy-account recovery are not yet implemented; do not use this basic registration flow where verified identity is a business requirement without adding those controls.

The API does not expose a public user-directory or arbitrary account-creation endpoint. Account registration only creates an account for the email address supplied; email ownership is not verified by this assignment version.

## Credit endpoints

- `GET /api/credits/{user_id}`
- `POST /api/credits/{user_id}/add` body `{"amount": positiveInteger}`
- `POST /api/credits/{user_id}/deduct` body `{"amount": positiveInteger}`
- `PATCH /api/credits/{user_id}/reset`

The backend enforces positive-integer amounts and prevents a deduction from making a balance negative. A normal signed-in user can only read their own balance. Credit mutations require the separate operator key, and an operator can act on another account only when both valid credentials are supplied.

## Schema administration

Use `X-API-Key: <ADMIN_API_KEY>` for:

- `GET /api/schema/migrations`
- `POST /api/schema/apply` with `{"migration_name":"add_index_on_credits","sql":"CREATE INDEX IF NOT EXISTS idx_credits_updated ON credits(last_updated DESC);" }`

Set both `ADMIN_API_KEY` and `CREDIT_ADMIN_API_KEY` to different high-entropy secrets of at least 32 characters each. The migration endpoint accepts only a single plain `CREATE INDEX` statement against an existing application table and an allowlisted column. It rejects `CREATE TABLE`, `ALTER TABLE`, table-copy/rename operations, unknown tables/columns, SQL comments, and multiple statements. This intentionally narrow interface is not a general SQL console; structural schema changes must be reviewed and deployed with the backend's versioned schema. The separate credit-operator key is required for balance mutations. Treat both keys as privileged credentials. Keep it out of source control and browser build variables; the frontend accepts it at runtime and holds it only in component memory. Use a least-privileged database role, restrict network access, and review SQL before applying it.

## Frontend connection and CORS

The companion frontend defaults to `http://localhost:8000` for local development. Set `VITE_API_BASE_URL` to the actual deployed API origin in the frontend host's environment and set `CORS_ORIGINS` to exact allowed frontend origins, such as:

```env
CORS_ORIGINS=http://localhost:5173,https://your-frontend.example.com
```

The `Authorization` and `X-API-Key` headers are explicitly allowed by CORS for bearer authentication and privileged operator actions. Never put `ADMIN_API_KEY`, database credentials, or other secrets in a `VITE_` variable; frontend build variables are visible to the browser.
