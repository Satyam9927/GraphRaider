#!/bin/bash
# ============================================================
#  GraphRaider container entrypoint — runs the backend and the
#  frontend together, and bootstraps config.json on the volume.
# ============================================================
set -e

CONFIG_FILE="${GRAPHRAIDER_CONFIG:-/app/backend/config.json}"

# Bootstrap config.json from the example if it doesn't exist yet.
mkdir -p "$(dirname "$CONFIG_FILE")"
if [ ! -f "$CONFIG_FILE" ]; then
  cp /app/backend/config.example.json "$CONFIG_FILE"
  echo "[config] created $CONFIG_FILE from example"
else
  echo "[config] using existing $CONFIG_FILE"
fi

# Start backend (FastAPI :8000)
cd /app/backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Start frontend (Express :3000)
cd /app/frontend
node server.js &
FRONTEND_PID=$!

echo "  GraphRaider running — UI http://localhost:3000  ·  API http://localhost:8000"

# Clean shutdown on SIGTERM/SIGINT, and exit if either process dies.
trap 'kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true' TERM INT
wait -n "$BACKEND_PID" "$FRONTEND_PID"
kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
