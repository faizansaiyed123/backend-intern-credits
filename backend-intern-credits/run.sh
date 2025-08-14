#!/usr/bin/env bash
export PYTHONUNBUFFERED=1
uvicorn main:app --host 0.0.0.0 --port 8000
