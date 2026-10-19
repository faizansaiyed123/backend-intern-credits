try:
    from .main import app as core_app
    from .scheduler import start_scheduler
except ImportError:  # Supports running from the src directory as well.
    from main import app as core_app
    from scheduler import start_scheduler

app = core_app
start_scheduler()
