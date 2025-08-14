from fastapi import FastAPI
from main import app as core_app
from scheduler import start_scheduler

app = core_app
start_scheduler()
