#!/usr/bin/env bash
export PYTHONUNBUFFERED=1
uvicorn app_with_scheduler:app --host 0.0.0.0 --port 8000
