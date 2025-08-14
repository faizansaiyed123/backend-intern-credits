-- schema.sql (PostgreSQL compatible)
-- LawVriksh Backend Intern Assignments - Credit Management

CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Each user has exactly one credit row
CREATE TABLE IF NOT EXISTS credits (
    user_id INTEGER PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    credits INTEGER NOT NULL DEFAULT 0 CHECK (credits >= 0),
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Track schema updates applied via external API
CREATE TABLE IF NOT EXISTS schema_migrations (
    id SERIAL PRIMARY KEY,
    migration_name TEXT UNIQUE NOT NULL,
    sql_text TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_by TEXT DEFAULT 'api'
);

-- Helpful index for auditing
CREATE INDEX IF NOT EXISTS idx_schema_migrations_applied_at ON schema_migrations(applied_at DESC);
