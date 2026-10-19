from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, timezone

try:
    from .db import run_sql
except ImportError:  # Supports running from the src directory as well.
    from db import run_sql

scheduler = BackgroundScheduler(timezone="UTC")


def add_daily_credits():
    # Ensure rows exist for all users who might not yet have a credits row.
    run_sql(
        "INSERT INTO credits (user_id) SELECT user_id FROM users u "
        "WHERE NOT EXISTS (SELECT 1 FROM credits c WHERE c.user_id=u.user_id)"
    )
    run_sql("UPDATE credits SET credits = credits + 5, last_updated = NOW()")
    print(f"[{datetime.now(timezone.utc)}] Daily credits added.")


def start_scheduler():
    # Run daily at midnight UTC.
    if not scheduler.get_job("daily-credit-refresh"):
        scheduler.add_job(
            add_daily_credits,
            CronTrigger(hour=0, minute=0),
            id="daily-credit-refresh",
            replace_existing=True,
        )
    if not scheduler.running:
        scheduler.start()
