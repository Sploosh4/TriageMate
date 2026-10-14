#!/usr/bin/env bash
# Poll a background job started by run_background.sh.
#
# Usage: scripts/poll_background.sh <job_name>
# Exit code: 0 = done, 1 = still running, 2 = failed, 3 = unknown job

set -euo pipefail

JOB_DIR="/tmp/triagemate/jobs"
JOB_NAME="${1:-}"

if [ -z "$JOB_NAME" ]; then
  echo "usage: scripts/poll_background.sh <job_name>"
  exit 3
fi

PIDFILE="$JOB_DIR/$JOB_NAME.pid"
LOG="$JOB_DIR/$JOB_NAME.log"
DONE="$JOB_DIR/$JOB_NAME.done"

if [ ! -f "$PIDFILE" ]; then
  echo "Unknown job '$JOB_NAME' (no pid file)"
  exit 3
fi

PID=$(cat "$PIDFILE")

if [ -f "$DONE" ]; then
  CODE=$(cat "$DONE")
  echo "Job '$JOB_NAME' FINISHED with exit code $CODE"
  echo "Last log lines:"
  tail -n 8 "$LOG" || true
  if [ "$CODE" -eq 0 ]; then
    exit 0
  else
    exit 2
  fi
fi

if kill -0 "$PID" 2>/dev/null; then
  echo "Job '$JOB_NAME' still running (pid $PID). Last log lines:"
  tail -n 5 "$LOG" || true
  exit 1
else
  echo "Job '$JOB_NAME' process gone without done marker — checking log:"
  tail -n 10 "$LOG" || true
  exit 2
fi
