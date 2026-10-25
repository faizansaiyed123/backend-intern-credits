import base64
import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

try:
    from .db import run_sql, engine
except ImportError:
    from db import run_sql, engine


app = FastAPI(title="LawVriksh Credits API", version="1.1.0")

allowed_origins = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

PASSWORD_ITERATIONS = 310_000
SESSION_LIFETIME = timedelta(hours=8)
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+$")
SAFE_INDEX_STATEMENT = re.compile(
    r"^CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"[A-Za-z_][A-Za-z0-9_$]*\s+ON\s+"
    r"(?P<table>[A-Za-z_][A-Za-z0-9_$]*)\s*"
    r"\(\s*(?P<columns>[A-Za-z_][A-Za-z0-9_$]*(?:\s+(?:ASC|DESC))?"
    r"(?:\s*,\s*[A-Za-z_][A-Za-z0-9_$]*(?:\s+(?:ASC|DESC))?)*)\s*\)$",
    re.IGNORECASE,
)
ALLOWED_INDEX_COLUMNS = {
    "users": {"user_id", "email", "created_at"},
    "credits": {"user_id", "last_updated"},
    "schema_migrations": {"id", "migration_name", "applied_at"},
    "auth_sessions": {"session_id", "user_id", "token_hash", "expires_at", "revoked_at"},
}


class RegisterInput(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=128)


class LoginInput(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class Amount(BaseModel):
    amount: int = Field(gt=0, le=2_147_483_647)


class SchemaApply(BaseModel):
    migration_name: str = Field(min_length=1, max_length=200)
    sql: str = Field(min_length=1, max_length=10_000)


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if len(normalized) > 255 or not EMAIL_PATTERN.fullmatch(normalized):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    return normalized


LOGIN_MAX_ATTEMPTS = 10


def login_fingerprint(email: str, client_host: str) -> str:
    # Include the direct client address so one network cannot lock out an account
    # for everyone else. Store only the one-way fingerprint, never the raw email/IP.
    material = email + "\0" + client_host
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def check_login_allowed(email: str, client_host: str) -> None:
    fingerprint = login_fingerprint(email, client_host)
    row = run_sql(
        """
        INSERT INTO auth_login_attempts (email_hash, attempts, window_started_at, blocked_until)
        VALUES (:email_hash, 1, NOW(), NULL)
        ON CONFLICT (email_hash) DO UPDATE SET
            attempts = CASE
                WHEN auth_login_attempts.window_started_at < NOW() - INTERVAL '15 minutes'
                     OR (auth_login_attempts.blocked_until IS NOT NULL
                         AND auth_login_attempts.blocked_until <= NOW())
                THEN 1 ELSE auth_login_attempts.attempts + 1 END,
            window_started_at = CASE
                WHEN auth_login_attempts.window_started_at < NOW() - INTERVAL '15 minutes'
                     OR (auth_login_attempts.blocked_until IS NOT NULL
                         AND auth_login_attempts.blocked_until <= NOW())
                THEN NOW() ELSE auth_login_attempts.window_started_at END,
            blocked_until = CASE
                WHEN auth_login_attempts.window_started_at < NOW() - INTERVAL '15 minutes'
                     OR (auth_login_attempts.blocked_until IS NOT NULL
                         AND auth_login_attempts.blocked_until <= NOW())
                THEN NULL
                WHEN auth_login_attempts.attempts + 1 > :max_attempts
                THEN NOW() + INTERVAL '15 minutes'
                ELSE auth_login_attempts.blocked_until END
        RETURNING (blocked_until IS NOT NULL AND blocked_until > NOW()) AS blocked
        """,
        {"email_hash": fingerprint, "max_attempts": LOGIN_MAX_ATTEMPTS},
    ).mappings().first()
    if row and row["blocked"]:
        raise HTTPException(
            status_code=429,
            detail="Too many sign-in attempts. Try again in 15 minutes.",
            headers={"Retry-After": "900"},
        )


def clear_login_failures(email: str, client_host: str) -> None:
    run_sql(
        """
        UPDATE auth_login_attempts
        SET attempts = 0, window_started_at = NOW(), blocked_until = NULL
        WHERE email_hash = :email_hash
        """,
        {"email_hash": login_fingerprint(email, client_host)},
    )

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    digest_text = base64.urlsafe_b64encode(derived).decode("ascii").rstrip("=")
    return "pbkdf2_sha256$" + str(PASSWORD_ITERATIONS) + "$" + salt_text + "$" + digest_text


def verify_password(password: str, stored_hash: Optional[str]) -> bool:
    if not stored_hash:
        return False
    try:
        algorithm, iterations_text, salt_text, expected_text = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        if iterations < 100_000 or iterations > 2_000_000:
            return False
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected = base64.urlsafe_b64decode(expected_text + "=" * (-len(expected_text) % 4))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def issue_session(connection, user_id: int) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + SESSION_LIFETIME
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    connection.execute(
        text(
            "INSERT INTO auth_sessions (user_id, token_hash, expires_at) "
            "VALUES (:uid, :token_hash, :expires_at)"
        ),
        {"uid": user_id, "token_hash": token_hash, "expires_at": expires_at},
    )
    return token, expires_at


def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Sign in to continue")
    token = authorization[7:].strip()
    if not token or len(token) > 500:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = run_sql(
        "SELECT u.user_id, u.email, u.name FROM auth_sessions s "
        "JOIN users u ON u.user_id = s.user_id "
        "WHERE s.token_hash = :token_hash AND s.revoked_at IS NULL "
        "AND s.expires_at > NOW()",
        {"token_hash": token_hash},
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return row


def configured_admin_key() -> Optional[str]:
    candidate = os.getenv("ADMIN_API_KEY")
    return candidate if candidate and len(candidate) >= 32 else None


def configured_credit_admin_key() -> Optional[str]:
    candidate = os.getenv("CREDIT_ADMIN_API_KEY")
    return candidate if candidate and len(candidate) >= 32 else None


def has_admin_access(candidate: Optional[str]) -> bool:
    configured_key = configured_admin_key()
    return bool(configured_key and candidate and hmac.compare_digest(candidate, configured_key))


def has_credit_admin_access(candidate: Optional[str]) -> bool:
    configured_key = configured_credit_admin_key()
    return bool(configured_key and candidate and hmac.compare_digest(candidate, configured_key))


def admin_guard(x_api_key: Optional[str] = Header(None)):
    if not configured_admin_key():
        raise HTTPException(status_code=503, detail="Schema admin API is not configured with a strong key")
    if not has_admin_access(x_api_key):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True


def credit_admin_guard(x_api_key: Optional[str] = Header(None)):
    if not configured_credit_admin_key():
        raise HTTPException(status_code=503, detail="Credit operator access is not configured with a strong key")
    if not has_credit_admin_access(x_api_key):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True


def require_account_access(user_id: int, current_user, x_api_key: Optional[str] = None):
    # A normal account can only read itself. A trusted operator may select another account.
    if int(current_user["user_id"]) != user_id and not has_credit_admin_access(x_api_key):
        # Conceal whether a different user's account ID exists.
        raise HTTPException(status_code=404, detail="User not found")


def get_user(user_id: int):
    row = run_sql(
        "SELECT user_id, email, name FROM users WHERE user_id=:uid",
        {"uid": user_id},
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return row


def ensure_credit_row(user_id: int):
    run_sql(
        "INSERT INTO credits (user_id) VALUES (:uid) ON CONFLICT (user_id) DO NOTHING",
        {"uid": user_id},
    )


@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterInput):
    email = normalize_email(payload.email)
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Name is required")
    password_hash = hash_password(payload.password)
    try:
        with engine.begin() as connection:
            row = connection.execute(
                text(
                    "INSERT INTO users (email, name, password_hash) "
                    "VALUES (:email, :name, :password_hash) "
                    "ON CONFLICT (email) DO NOTHING "
                    "RETURNING user_id, email, name"
                ),
                {"email": email, "name": name, "password_hash": password_hash},
            ).mappings().first()
            if not row:
                raise HTTPException(status_code=409, detail="Unable to create an account with those details")
            user_id = int(row["user_id"])
            connection.execute(
                text("INSERT INTO credits (user_id, credits) VALUES (:uid, 0)"),
                {"uid": user_id},
            )
            token, expires_at = issue_session(connection, user_id)
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Unable to create an account with those details") from None
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "user": {"user_id": user_id, "email": row["email"], "name": row["name"]},
    }


@app.post("/api/auth/login")
def login(payload: LoginInput, request: Request):
    email = normalize_email(payload.email)
    client_host = request.client.host if request.client else "unknown"
    check_login_allowed(email, client_host)
    row = run_sql(
        "SELECT user_id, email, name, password_hash FROM users WHERE email=:email",
        {"email": email},
    ).mappings().first()
    valid_password = bool(row and verify_password(payload.password, row["password_hash"]))
    if not row:
        # Keep an unknown email from being substantially cheaper to probe.
        dummy = "pbkdf2_sha256$310000$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        verify_password(payload.password, dummy)
    if not valid_password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    clear_login_failures(email, client_host)
    with engine.begin() as connection:
        token, expires_at = issue_session(connection, int(row["user_id"]))
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "user": {"user_id": row["user_id"], "email": row["email"], "name": row["name"]},
    }


@app.get("/api/auth/me")
def who_am_i(current_user=Depends(get_current_user)):
    return dict(current_user)


@app.post("/api/auth/logout")
def logout(
    authorization: Optional[str] = Header(None),
    current_user=Depends(get_current_user),
):
    token = authorization[7:].strip()
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    run_sql(
        "UPDATE auth_sessions SET revoked_at=NOW() "
        "WHERE token_hash=:token_hash AND user_id=:uid AND revoked_at IS NULL",
        {"token_hash": token_hash, "uid": current_user["user_id"]},
    )
    return {"ok": True}


@app.get("/api/credits/{user_id}")
def get_credits(
    user_id: int,
    current_user=Depends(get_current_user),
    x_api_key: Optional[str] = Header(None),
):
    require_account_access(user_id, current_user, x_api_key)
    get_user(user_id)
    row = run_sql(
        "SELECT credits, last_updated FROM credits WHERE user_id=:uid",
        {"uid": user_id},
    ).mappings().first()
    if not row:
        ensure_credit_row(user_id)
        row = {"credits": 0, "last_updated": datetime.now(timezone.utc)}
    return {
        "user_id": user_id,
        "credits": row["credits"],
        "last_updated": row["last_updated"],
    }


@app.post("/api/credits/{user_id}/add")
def add_credits(
    user_id: int,
    body: Amount,
    current_user=Depends(get_current_user),
    _: bool = Depends(credit_admin_guard),
    x_api_key: Optional[str] = Header(None),
):
    require_account_access(user_id, current_user, x_api_key)
    get_user(user_id)
    ensure_credit_row(user_id)
    updated = run_sql(
        "UPDATE credits SET credits = credits + :amt, last_updated = NOW() "
        "WHERE user_id = :uid AND credits <= :max_balance - :amt",
        {"uid": user_id, "amt": body.amount, "max_balance": 2_147_483_647},
    ).rowcount
    if updated == 0:
        raise HTTPException(status_code=400, detail="Credit balance limit exceeded")
    return get_credits(user_id, current_user, x_api_key)


@app.post("/api/credits/{user_id}/deduct")
def deduct_credits(
    user_id: int,
    body: Amount,
    current_user=Depends(get_current_user),
    _: bool = Depends(credit_admin_guard),
    x_api_key: Optional[str] = Header(None),
):
    require_account_access(user_id, current_user, x_api_key)
    get_user(user_id)
    ensure_credit_row(user_id)
    updated = run_sql(
        "UPDATE credits SET credits = credits - :amt, last_updated = NOW() WHERE user_id = :uid AND credits >= :amt",
        {"uid": user_id, "amt": body.amount},
    ).rowcount
    if updated == 0:
        raise HTTPException(status_code=400, detail="Insufficient credits")
    return get_credits(user_id, current_user, x_api_key)


@app.patch("/api/credits/{user_id}/reset")
def reset_credits(
    user_id: int,
    current_user=Depends(get_current_user),
    _: bool = Depends(credit_admin_guard),
    x_api_key: Optional[str] = Header(None),
):
    require_account_access(user_id, current_user, x_api_key)
    get_user(user_id)
    ensure_credit_row(user_id)
    run_sql(
        "UPDATE credits SET credits = 0, last_updated = NOW() WHERE user_id = :uid",
        {"uid": user_id},
    )
    return get_credits(user_id, current_user, x_api_key)


def validate_migration_sql(sql_text: str) -> str:
    statement = sql_text.strip()
    if not statement:
        raise HTTPException(status_code=422, detail="SQL statement is required")
    if len(statement) > 10_000:
        raise HTTPException(status_code=422, detail="SQL statement is too long")
    # Do not expose a general-purpose SQL console. Accept only plain index creation
    # on known application tables and explicitly approved columns.
    if ";" in statement[:-1] or "--" in statement or "/*" in statement or "*/" in statement:
        raise HTTPException(status_code=400, detail="Use one index statement without inline SQL comments")
    statement = statement[:-1].rstrip() if statement.endswith(";") else statement
    match = SAFE_INDEX_STATEMENT.fullmatch(statement)
    if not match:
        raise HTTPException(
            status_code=400,
            detail="Only CREATE INDEX statements on approved application columns are allowed",
        )
    table = match.group("table").lower()
    if table not in ALLOWED_INDEX_COLUMNS:
        raise HTTPException(status_code=400, detail="Index target table is not allowed")
    columns = re.split(r"\s*,\s*", match.group("columns"))
    for column_spec in columns:
        column_match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_$]*)(?:\s+(?:ASC|DESC))?", column_spec.strip(), re.IGNORECASE)
        if not column_match or column_match.group(1).lower() not in ALLOWED_INDEX_COLUMNS[table]:
            raise HTTPException(status_code=400, detail="Index target column is not allowed")
    return statement

@app.get("/api/schema/migrations")
def list_migrations(_: bool = Depends(admin_guard)):
    rows = run_sql(
        "SELECT id, migration_name, applied_at FROM schema_migrations ORDER BY applied_at DESC"
    ).mappings().all()
    return {"migrations": rows}


@app.post("/api/schema/apply")
def apply_schema(payload: SchemaApply, _: bool = Depends(admin_guard)):
    statement = validate_migration_sql(payload.sql)
    migration_name = payload.migration_name.strip()
    if not migration_name:
        raise HTTPException(status_code=422, detail="Migration name is required")
    with engine.begin() as connection:
        exists = connection.execute(
            text("SELECT 1 FROM schema_migrations WHERE migration_name=:n"),
            {"n": migration_name},
        ).first()
        if exists:
            return {
                "status": "skipped",
                "reason": "already_applied",
                "migration_name": migration_name,
            }
        connection.execute(text(statement))
        connection.execute(
            text("INSERT INTO schema_migrations (migration_name, sql_text) VALUES (:n, :s)"),
            {"n": migration_name, "s": statement},
        )
    return {"status": "applied", "migration_name": migration_name}


@app.get("/healthz")
def health():
    return {"ok": True, "time": datetime.now(timezone.utc).isoformat()}
