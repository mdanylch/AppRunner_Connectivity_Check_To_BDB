#!/bin/sh
# App Runner start command: `sh run.sh`
# PYTHONUNBUFFERED + python -u: stdout/stderr flush immediately so CloudWatch
# application logs show lines without waiting for buffer fills.
set -e
export PORT="${PORT:-8080}"
export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"
export PYTHONPATH="/app/vendor${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -u app.py
