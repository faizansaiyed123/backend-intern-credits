import base64
import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
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
SAFE_MIGRATION_START = re.compile(
    r"^\s*(?:CREATE\s+(?:UNIQUE\s+)?INDEX\b|CREATE\s+TABLE\b|"
    r"ALTER\s+TABLE\b|CREATE\s+SEQUENCE\b|ALTER\s+SEQUENCE\b)",
    re.IGNORECASE,
)
FORBIDDEN_MIGRATION_KEYWORDS = re.compile(
    r"\b(?:DROP|TRUNCATE|DELETE|UPDATE|INSERT|UPSERT|MERGE|COPY|CALL|DO|"
    r"GRANT|REVOKE|EXECUTE|VACUUM|ANALYZE|SECURITY|OWNER|RESET|COMMIT|ROLLBACK)\b",
    re.IGNORECASE,
)


class RegisterInput(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=128)


class LoginInput(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class Amount(BaseModel):
    amount: int = Field(gt=0)


class SchemaApply(BaseModel):
    migration_name: str = Field(min_length=1, max_length=200)
    sql: str = Field(min_length=1, max_length=10_000)


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if len(normalized) > 255 or not EMAIL_PATTERN.fullmatch(normalized):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    return normalized


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


def has_admin_access(candidate: Optional[str]) -> bool:
    configured_key = configured_admin_key()
    return bool(configured_key and candidate and hmac.compare_digest(candidate, configured_key))


def require_account_access(user_id: int, current_user, x_api_key: Optional[str] = None):
    # A normal account can only read itself. A trusted operator may select another account.
    if int(current_user["user_id"]) != user_id and not has_admin_access(x_api_key):
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
def login(payload: LoginInput):
    email = normalize_email(payload.email)
    row = run_sql(
        "SELECT user_id, email, name, password_hash FROM users WHERE email=:email",
        {"email": email},
    ).mappings().first()
    if not row:
        # A dummy hash calculation reduces timing-based email discovery.
        dummy = "pbkdf2_sha256$310000$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        verify_password(payload.password, dummy)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
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
    _: bool = Depends(lambda x_api_key=Header(None): admin_guard(x_api_key)),
    x_api_key: Optional[str] = Header(None),
):
    require_account_access(user_id, current_user, x_api_key)
    get_user(user_id)
    ensure_credit_row(user_id)
    run_sql(
        "UPDATE credits SET credits = credits + :amt, last_updated = NOW() WHERE user_id = :uid",
        {"uid": user_id, "amt": body.amount},
    )
    return get_credits(user_id, current_user, x_api_key)


@app.post("/api/credits/{user_id}/deduct")
def deduct_credits(
    user_id: int,
    body: Amount,
    current_user=Depends(get_current_user),
    _: bool = Depends(lambda x_api_key=Header(None): admin_guard(x_api_key)),
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
    _: bool = Depends(lambda x_api_key=Header(None): admin_guard(x_api_key)),
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
    # Keep this endpoint to a single, non-destructive schema statement. This prevents
    # using the migration UI as an arbitrary SQL console, even with a valid admin key.
    if ";" in statement[:-1] or "--" in statement or "/*" in statement or "*/" in statement:
        raise HTTPException(status_code=400, detail="Use one schema statement without inline SQL comments")
    statement = statement[:-1].rstrip() if statement.endswith(";") else statement
    if not SAFE_MIGRATION_START.match(statement) or FORBIDDEN_MIGRATION_KEYWORDS.search(statement):
        raise HTTPException(
            status_code=400,
            detail="Only non-destructive CREATE/ALTER TABLE, INDEX, or SEQUENCE statements are allowed",
        )
    return statement


def admin_guard(x_api_key: Optional[str] = Header(None)):
    if not configured_admin_key():
        raise HTTPException(status_code=503, detail="Admin API is not configured with a strong key")
    if not has_admin_access(x_api_key):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True


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
