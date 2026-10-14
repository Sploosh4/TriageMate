#!/usr/bin/env bash
# Run a long job fully detached so the agent is never blocked, with a
# log file and PID for 10-minute-interval polling.
#
# Usage:
#   scripts/run_background.sh "<command>" <job_name>
#
# Writes:
#   /tmp/triagemate/jobs/<job_name>.log
#   /tmp/triagemate/jobs/<job_name>.pid
# Prints the PID on success.
#
# Poll with:  scripts/poll_background.sh <job_name>

set -euo pipefail

JOB_DIR="/tmp/triagemate/jobs"
mkdir -p "$JOB_DIR"

CMD="$1"
JOB_NAME="${2:-job-$(date +%s)}"

LOG="$JOB_DIR/$JOB_NAME.log"
PIDFILE="$JOB_DIR/$JOB_NAME.pid"
DONE="$JOB_DIR/$JOB_NAME.done"

rm -f "$DONE"

# Keep one wrapper as the recorded process. It forwards stop signals to the
# actual command and waits for it, so a stopped job cannot leave an orphan.
# The inner shell expands its own variables.
# shellcheck disable=SC2016
setsid bash -c '
  command_text=$1
  log_path=$2
  done_path=$3
  child_pid=""

  stop_child() {
    trap - TERM INT HUP
    if [[ -n "$child_pid" ]] && kill -0 "$child_pid" 2>/dev/null; then
      kill -TERM -- "-$child_pid"
      wait "$child_pid"
      status=$?
    else
      status=143
    fi
    printf "%s\n" "$status" >"$done_path"
    exit "$status"
  }

  trap stop_child TERM INT HUP
  setsid bash -c "$command_text" >"$log_path" 2>&1 &
  child_pid=$!
  wait "$child_pid"
  status=$?
  printf "%s\n" "$status" >"$done_path"
  exit "$status"
' _ "$CMD" "$LOG" "$DONE" </dev/null >/dev/null 2>&1 &
PID=$!
echo "$PID" > "$PIDFILE"
echo "Started job '$JOB_NAME' pid=$PID log=$LOG"
echo "Poll: scripts/poll_background.sh $JOB_NAME"
