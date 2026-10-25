-- schema.sql (PostgreSQL compatible)
-- LawVriksh Backend Intern Assignments - Credit Management

CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    password_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Safe, repeatable upgrade for databases created before authentication was added.
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;

-- Opaque bearer sessions are stored only as SHA-256 hashes and can be revoked on logout.
CREATE TABLE IF NOT EXISTS auth_sessions (
    session_id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash CHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_expiry
    ON auth_sessions(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry
    ON auth_sessions(expires_at);

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


-- Track failed sign-in attempts by a one-way email fingerprint, not by storing raw email again.
CREATE TABLE IF NOT EXISTS auth_login_attempts (
    email_hash CHAR(64) PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blocked_until TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_blocked_until
    ON auth_login_attempts(blocked_until);
