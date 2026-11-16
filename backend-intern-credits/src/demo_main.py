from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="Mintline Demo API", version="1.0.0")

origins = [
    origin.strip().rstrip("/")
    for origin in os.getenv("DEMO_CORS_ORIGINS", "*").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

DEMO_EMAIL = "demo@mintline.app"
DEMO_PASSWORD = "MintlineDemo2026!"
DEMO_CREDIT_ADMIN_KEY = "mintline-demo-credit-operator"
DEMO_SCHEMA_ADMIN_KEY = "mintline-demo-schema-admin"
SESSION_LIFETIME = timedelta(hours=8)
PASSWORD_ITERATIONS = 120_000
MAX_BALANCE = 2_147_483_647
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

lock = threading.RLock()
users: dict[int, dict] = {}
email_to_id: dict[str, int] = {}
credits: dict[int, dict] = {}
sessions: dict[str, dict] = {}
migrations: list[dict] = []
daily_runs: set[str] = set()
next_user_id = 1
next_migration_id = 1


class RegisterInput(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=128)


class LoginInput(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class Amount(BaseModel):
    amount: int = Field(gt=0, le=MAX_BALANCE)


class SchemaApply(BaseModel):
    migration_name: str = Field(min_length=1, max_length=200)
    sql: str = Field(min_length=1, max_length=10_000)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def password_hash(password: str, salt: Optional[bytes] = None) -> str:
    actual_salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), actual_salt, PASSWORD_ITERATIONS
    )
    return actual_salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            PASSWORD_ITERATIONS,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if len(normalized) > 255 or not EMAIL_PATTERN.fullmatch(normalized):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    return normalized


def public_user(user: dict) -> dict:
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "name": user["name"],
    }


def issue_session(user_id: int) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    expires_at = now_utc() + SESSION_LIFETIME
    sessions[token] = {"user_id": user_id, "expires_at": expires_at}
    return token, expires_at.isoformat()


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization[7:].strip()
    with lock:
        session = sessions.get(token)
        if not session or session["expires_at"] <= now_utc():
            sessions.pop(token, None)
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        user = users.get(session["user_id"])
        if not user:
            raise HTTPException(status_code=401, detail="Invalid session")
        return public_user(user)


def credit_admin_guard(x_api_key: Optional[str] = Header(None)) -> bool:
    if not x_api_key or not hmac.compare_digest(x_api_key, DEMO_CREDIT_ADMIN_KEY):
        raise HTTPException(status_code=403, detail="Credit operator authorization required")
    return True


def admin_guard(x_api_key: Optional[str] = Header(None)) -> bool:
    if not x_api_key or not hmac.compare_digest(x_api_key, DEMO_SCHEMA_ADMIN_KEY):
        raise HTTPException(status_code=401, detail="Schema administrator authorization required")
    return True


def require_account_access(user_id: int, current_user: dict, x_api_key: Optional[str]) -> None:
    if current_user["user_id"] != user_id:
        if not x_api_key or not hmac.compare_digest(x_api_key, DEMO_CREDIT_ADMIN_KEY):
            raise HTTPException(status_code=404, detail="User not found")


def require_user(user_id: int) -> dict:
    user = users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def account_snapshot(user_id: int) -> dict:
    record = credits[user_id]
    return {
        "user_id": user_id,
        "credits": record["credits"],
        "last_updated": record["last_updated"],
    }


def validate_migration_sql(sql_text: str) -> str:
    statement = sql_text.strip()
    if not statement:
        raise HTTPException(status_code=422, detail="SQL statement is required")
    if len(statement) > 10_000:
        raise HTTPException(status_code=422, detail="SQL statement is too long")
    if ";" in statement[:-1] or "--" in statement or "/*" in statement or "*/" in statement:
        raise HTTPException(
            status_code=400,
            detail="Use one index statement without inline SQL comments",
        )
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
    for item in columns:
        column_match = re.fullmatch(
            r"([A-Za-z_][A-Za-z0-9_$]*)(?:\s+(?:ASC|DESC))?",
            item.strip(),
            re.IGNORECASE,
        )
        if not column_match or column_match.group(1).lower() not in ALLOWED_INDEX_COLUMNS[table]:
            raise HTTPException(status_code=400, detail="Index target column is not allowed")
    return statement


def reset_demo_state() -> None:
    global next_user_id, next_migration_id
    with lock:
        users.clear()
        email_to_id.clear()
        credits.clear()
        sessions.clear()
        migrations.clear()
        daily_runs.clear()
        next_user_id = 1
        next_migration_id = 1

        seed_users = [
            (DEMO_EMAIL, "Demo Workspace", DEMO_PASSWORD, 1280),
            ("operations@mintline.app", "Operations Team", "OperationsDemo2026!", 760),
        ]
        for email, name, password, balance in seed_users:
            user_id = next_user_id
            next_user_id += 1
            normalized = normalize_email(email)
            users[user_id] = {
                "user_id": user_id,
                "email": normalized,
                "name": name,
                "password_hash": password_hash(password),
            }
            email_to_id[normalized] = user_id
            credits[user_id] = {"credits": balance, "last_updated": now_utc()}

        migrations.append(
            {
                "id": next_migration_id,
                "migration_name": "create_credit_workspace_indexes",
                "applied_at": datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc),
            }
        )
        next_migration_id += 1


reset_demo_state()


@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterInput):
    global next_user_id
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Name is required")
    email = normalize_email(payload.email)
    with lock:
        if email in email_to_id:
            raise HTTPException(
                status_code=409,
                detail="Unable to create an account with those details",
            )
        user_id = next_user_id
        user = {
            "user_id": user_id,
            "email": email,
            "name": name,
            "password_hash": password_hash(payload.password),
        }
        users[user_id] = user
        email_to_id[email] = user_id
        credits[user_id] = {"credits": 0, "last_updated": now_utc()}
        next_user_id += 1
        token, expires_at = issue_session(user_id)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "user": public_user(user),
    }


@app.post("/api/auth/login")
def login(payload: LoginInput):
    email = normalize_email(payload.email)
    with lock:
        user_id = email_to_id.get(email)
        user = users.get(user_id) if user_id is not None else None
        if not user or not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token, expires_at = issue_session(user_id)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "user": public_user(user),
    }


@app.get("/api/auth/me")
def who_am_i(current_user: dict = Depends(get_current_user)):
    return current_user


@app.post("/api/auth/logout")
def logout(
    authorization: Optional[str] = Header(None),
    current_user: dict = Depends(get_current_user),
):
    token = authorization[7:].strip()
    with lock:
        sessions.pop(token, None)
    return {"ok": True}


@app.get("/api/credits/{user_id}")
def get_credits(
    user_id: int,
    current_user: dict = Depends(get_current_user),
    x_api_key: Optional[str] = Header(None),
):
    require_account_access(user_id, current_user, x_api_key)
    with lock:
        require_user(user_id)
        return account_snapshot(user_id)


@app.post("/api/credits/{user_id}/add")
def add_credits(
    user_id: int,
    body: Amount,
    current_user: dict = Depends(get_current_user),
    _: bool = Depends(credit_admin_guard),
    x_api_key: Optional[str] = Header(None),
):
    require_account_access(user_id, current_user, x_api_key)
    with lock:
        require_user(user_id)
        current = credits[user_id]["credits"]
        if current > MAX_BALANCE - body.amount:
            raise HTTPException(status_code=400, detail="Credit balance limit exceeded")
        credits[user_id]["credits"] = current + body.amount
        credits[user_id]["last_updated"] = now_utc()
        return account_snapshot(user_id)


@app.post("/api/credits/{user_id}/deduct")
def deduct_credits(
    user_id: int,
    body: Amount,
    current_user: dict = Depends(get_current_user),
    _: bool = Depends(credit_admin_guard),
    x_api_key: Optional[str] = Header(None),
):
    require_account_access(user_id, current_user, x_api_key)
    with lock:
        require_user(user_id)
        current = credits[user_id]["credits"]
        if current < body.amount:
            raise HTTPException(status_code=400, detail="Insufficient credits")
        credits[user_id]["credits"] = current - body.amount
        credits[user_id]["last_updated"] = now_utc()
        return account_snapshot(user_id)


@app.patch("/api/credits/{user_id}/reset")
def reset_credits(
    user_id: int,
    current_user: dict = Depends(get_current_user),
    _: bool = Depends(credit_admin_guard),
    x_api_key: Optional[str] = Header(None),
):
    with lock:
        require_account_access(user_id, current_user, x_api_key)
        require_user(user_id)
        credits[user_id]["credits"] = 0
        credits[user_id]["last_updated"] = now_utc()
        return account_snapshot(user_id)


@app.get("/api/schema/migrations")
def list_migrations(_: bool = Depends(admin_guard)):
    with lock:
        return {
            "migrations": sorted(
                migrations,
                key=lambda row: row["applied_at"],
                reverse=True,
            )
        }


@app.post("/api/schema/apply")
def apply_schema(payload: SchemaApply, _: bool = Depends(admin_guard)):
    global next_migration_id
    statement = validate_migration_sql(payload.sql)
    name = payload.migration_name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Migration name is required")

    with lock:
        if any(row["migration_name"] == name for row in migrations):
            return {
                "status": "skipped",
                "reason": "already_applied",
                "migration_name": name,
            }
        migrations.append(
            {
                "id": next_migration_id,
                "migration_name": name,
                "applied_at": now_utc(),
            }
        )
        next_migration_id += 1
    # This endpoint records metadata only. It never opens a DB connection or executes SQL.
    return {"status": "applied", "migration_name": name}


@app.post("/api/demo/scheduler/run-daily-credit-refresh")
def run_daily_credit_refresh(_: bool = Depends(credit_admin_guard)):
    run_date = now_utc().date().isoformat()
    with lock:
        if run_date in daily_runs:
            return {
                "status": "skipped",
                "reason": "already_applied",
                "run_date": run_date,
            }
        daily_runs.add(run_date)
        for user_id in users:
            credits[user_id]["credits"] += 5
            credits[user_id]["last_updated"] = now_utc()
    return {
        "status": "applied",
        "credits_added_per_account": 5,
        "run_date": run_date,
    }


@app.get("/healthz")
def health():
    return {"ok": True, "time": now_utc().isoformat()}
