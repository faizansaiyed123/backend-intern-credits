from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import text

try:
    from .db import engine
except ImportError:
    from db import engine

scheduler = BackgroundScheduler(timezone="UTC")


def add_daily_credits() -> bool:
    run_date = datetime.now(timezone.utc).date()
    with engine.begin() as connection:
        claimed = connection.execute(
            text(
                "INSERT INTO credit_daily_runs (run_date) VALUES (:run_date) "
                "ON CONFLICT (run_date) DO NOTHING RETURNING run_date"
            ),
            {"run_date": run_date},
        ).first()
        if not claimed:
            print(f"[{datetime.now(timezone.utc)}] Daily credit refresh already applied for {run_date}.")
            return False

        connection.execute(
            text(
                "INSERT INTO credits (user_id) "
                "SELECT user_id FROM users "
                "ON CONFLICT (user_id) DO NOTHING"
            )
        )
        connection.execute(
            text("UPDATE credits SET credits = credits + 5, last_updated = NOW()")
        )
        connection.execute(
            text(
                "DELETE FROM auth_login_attempts "
                "WHERE window_started_at < NOW() - INTERVAL '1 day'"
            )
        )

    print(f"[{datetime.now(timezone.utc)}] Daily credits added for {run_date}.")
    return True


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
