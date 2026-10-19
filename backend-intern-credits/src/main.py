import hmac
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import text

try:
    from .db import run_sql, engine
except ImportError:  # Supports running from the src directory as well.
    from db import run_sql, engine

app = FastAPI(title="LawVriksh Credits API", version="1.0.0")

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
    allow_headers=["Content-Type", "X-API-Key"],
)


class Amount(BaseModel):
    amount: int = Field(gt=0)


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


@app.get("/api/credits/{user_id}")
def get_credits(user_id: int):
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
def add_credits(user_id: int, body: Amount):
    get_user(user_id)
    ensure_credit_row(user_id)
    run_sql(
        "UPDATE credits SET credits = credits + :amt, last_updated = NOW() WHERE user_id = :uid",
        {"uid": user_id, "amt": body.amount},
    )
    return get_credits(user_id)


@app.post("/api/credits/{user_id}/deduct")
def deduct_credits(user_id: int, body: Amount):
    get_user(user_id)
    ensure_credit_row(user_id)
    updated = run_sql(
        "UPDATE credits SET credits = credits - :amt, last_updated = NOW() WHERE user_id = :uid AND credits >= :amt",
        {"uid": user_id, "amt": body.amount},
    ).rowcount
    if updated == 0:
        raise HTTPException(status_code=400, detail="Insufficient credits")
    return get_credits(user_id)


@app.patch("/api/credits/{user_id}/reset")
def reset_credits(user_id: int):
    get_user(user_id)
    ensure_credit_row(user_id)
    run_sql(
        "UPDATE credits SET credits = 0, last_updated = NOW() WHERE user_id = :uid",
        {"uid": user_id},
    )
    return get_credits(user_id)


class SchemaApply(BaseModel):
    migration_name: str = Field(min_length=1, max_length=200)
    sql: str = Field(min_length=1)


def admin_guard(x_api_key: Optional[str] = Header(None)):
    configured_key = os.getenv("ADMIN_API_KEY")
    if not configured_key:
        raise HTTPException(status_code=503, detail="Admin API is not configured on this server")
    if x_api_key is None or not hmac.compare_digest(x_api_key, configured_key):
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
    exists = run_sql(
        "SELECT 1 FROM schema_migrations WHERE migration_name=:n",
        {"n": payload.migration_name},
    ).first()
    if exists:
        return {
            "status": "skipped",
            "reason": "already_applied",
            "migration_name": payload.migration_name,
        }
    with engine.begin() as conn:
        conn.execute(text(payload.sql))
        conn.execute(
            text("INSERT INTO schema_migrations (migration_name, sql_text) VALUES (:n, :s)"),
            {"n": payload.migration_name, "s": payload.sql},
        )
    return {"status": "applied", "migration_name": payload.migration_name}


@app.get("/healthz")
def health():
    return {"ok": True, "time": datetime.now(timezone.utc).isoformat()}
