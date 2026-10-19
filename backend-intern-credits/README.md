# backend-intern-credits

LawVriksh Backend Intern Assignment 2 - Credit Management API & Schema

## Quick Start

Run these commands from the repository root:

```bash
cd backend-intern-credits
python -m venv .venv
source .venv/bin/activate
pip install -r src/requirements.txt
cp .env.example .env
# Edit .env and replace the database credentials and admin key.
set -a && source .env && set +a
psql "${DATABASE_URL/+psycopg/}" -f schema.sql
uvicorn src.main:app --reload
```

To run with the daily scheduler inside the same process, start the app from the same directory:
```bash
uvicorn src.app_with_scheduler:app --reload
```

Alternatively, schedule the daily job externally via cron. Configure the needed database connection environment variables in the cron environment; shell `.env` files are not loaded automatically:
```
0 0 * * * curl -s http://localhost:8000/healthz >/dev/null 2>&1 && psql "$DATABASE_URL" -c "INSERT INTO credits (user_id) SELECT user_id FROM users u WHERE NOT EXISTS (SELECT 1 FROM credits c WHERE c.user_id=u.user_id)"; psql "$DATABASE_URL" -c "UPDATE credits SET credits = credits + 5, last_updated = NOW();"
```

## External Schema Update

Protect with header `X-API-Key: <ADMIN_API_KEY>`

- `GET /api/schema/migrations`
- `POST /api/schema/apply` body:
```json
{ "migration_name": "add_index_on_credits", "sql": "CREATE INDEX IF NOT EXISTS idx_credits_updated ON credits(last_updated DESC);" }
```

The schema-apply endpoint executes SQL using the database role configured by `DATABASE_URL`. Keep it restricted to trusted administrators and do not expose the admin key in frontend build-time environment variables.

## Frontend connection and CORS

The companion frontend uses Vite and defaults to `http://localhost:8000` for the API. Set `VITE_API_BASE_URL` in the frontend environment when the API is hosted elsewhere.

The API allows the local Vite origins by default. For a deployed frontend, set `CORS_ORIGINS` to a comma-separated list of exact origins, for example:

```env
CORS_ORIGINS=http://localhost:5173,https://your-frontend.example.com
```

Restart the API after changing environment variables. The admin endpoints fail closed if `ADMIN_API_KEY` is missing; configure a strong key on the backend before using migration management.
