#!/usr/bin/env bash
# Restart the reader on a given port (default 5000).
#   ./restart.sh [port]
# Finds the previous instance by listening port rather than by command-line
# pattern — a pattern match tends to match the invoking shell itself.
set -uo pipefail
cd "$(dirname "$0")"

PORT="${1:-5000}"

PID=$(ss -lptnH "sport = :${PORT}" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1)
if [ -n "${PID:-}" ]; then
  kill "$PID" 2>/dev/null
  sleep 2
fi

MAIL_PORT="$PORT" nohup .venv/bin/python app.py > "reader-${PORT}.log" 2>&1 &

sleep 8
if curl -sf -o /dev/null "http://127.0.0.1:${PORT}/"; then
  echo "reader up on http://127.0.0.1:${PORT}"
else
  echo "reader failed to start; see reader-${PORT}.log"
  tail -20 "reader-${PORT}.log"
  exit 1
fi
