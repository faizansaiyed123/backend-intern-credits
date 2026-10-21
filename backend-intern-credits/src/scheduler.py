from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, timezone

try:
    from .db import run_sql
except ImportError:  
    from db import run_sql

scheduler = BackgroundScheduler(timezone="UTC")


def add_daily_credits():
    run_sql(
        "INSERT INTO credits (user_id) SELECT user_id FROM users u "
        "WHERE NOT EXISTS (SELECT 1 FROM credits c WHERE c.user_id=u.user_id)"
    )
    run_sql("UPDATE credits SET credits = credits + 5, last_updated = NOW()")
    print(f"[{datetime.now(timezone.utc)}] Daily credits added.")


def start_scheduler():
    if not scheduler.get_job("daily-credit-refresh"):
        scheduler.add_job(
            add_daily_credits,
            CronTrigger(hour=0, minute=0),
            id="daily-credit-refresh",
            replace_existing=True,
        )
    if not scheduler.running:
        scheduler.start()
