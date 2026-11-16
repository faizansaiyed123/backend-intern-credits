# Mintline demo backend

This \`demo\` branch adds a standalone, recruiter-safe FastAPI simulator for the Mintline credit workspace. The original PostgreSQL-backed API remains in \`src/main.py\`; this demo server is separate and does not import \`src.db\`, create a SQLAlchemy engine, read production database credentials, or connect to PostgreSQL.

## Run the demo API

From the \`backend-intern-credits\` directory:

\`\`\`bash
python -m venv .venv
source .venv/bin/activate
pip install -r demo-requirements.txt
uvicorn src.demo_main:app --reload --port 8001
\`\`\`

Open \`http://localhost:8001/docs\` to inspect the demo API.

## Seeded access

| Purpose | Value |
| --- | --- |
| Email | \`demo@mintline.app\` |
| Password | \`MintlineDemo2026!\` |
| Credit operator key | \`mintline-demo-credit-operator\` |
| Schema admin key | \`mintline-demo-schema-admin\` |

The simulator starts with two sample accounts: account 1 has 1,280 credits and account 2 has 760 credits. Registration creates a new zero-credit account.

## Implemented API contract

The demo server mirrors the companion frontend's API routes:

- \`POST /api/auth/register\`, \`POST /api/auth/login\`, \`GET /api/auth/me\`, and \`POST /api/auth/logout\`
- \`GET /api/credits/{user_id}\`
- \`POST /api/credits/{user_id}/add\`, \`POST /api/credits/{user_id}/deduct\`, and \`PATCH /api/credits/{user_id}/reset\`
- \`GET /api/schema/migrations\` and \`POST /api/schema/apply\`
- \`GET /healthz\`

A normal signed-in account can read only its own balance. Other-account reads require the demo operator key. Every add, deduct, or reset operation requires both a valid bearer session and the separate demo operator key. The schema history uses its own demo key.

## Deliberate simulation boundaries

- All API state is held in process memory and resets when the server restarts.
- Passwords are hashed with PBKDF2-HMAC-SHA256 and sessions expire after eight hours; this is still a demo service, not production identity infrastructure.
- The schema endpoint accepts only a restricted \`CREATE INDEX\` statement. It validates the statement and records migration metadata; **it never executes submitted SQL**.
- \`POST /api/demo/scheduler/run-daily-credit-refresh\` adds five credits to every sample account once per UTC date. Repeated calls on the same date are skipped.
- The sample keys are public and must never be reused as production credentials.

To connect the companion frontend demo to this API, set \`VITE_DEMO_MODE=true\` and \`VITE_DEMO_API_URL=http://localhost:8001\` in the frontend environment.

## Tests

\`\`\`bash
python -m pip install 'fastapi>=0.115,<1' 'httpx>=0.27,<1'
python -m unittest discover -s backend-intern-credits/tests -v
\`\`\`

The \`demo\` branch has its own CI workflow. It checks only this branch and has read-only repository permissions.
