#!/usr/bin/env bash
# ============================================================
#  start.sh - GraphRaider launcher (macOS / Linux)
#   * Creates backend/config.json from the example if missing
#   * Creates a Python venv, installs Python + Node deps
#   * Starts the FastAPI backend (8000) and Express frontend (3000)
#   * Opens the browser
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

cyan()  { printf "\033[36m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }
yellow(){ printf "\033[33m%s\033[0m\n" "$1"; }

echo ""
cyan "  ==================================================="
echo  "   GraphRaider  -  GraphQL Security Tester"
cyan "  ==================================================="
echo ""

# pick a python
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then echo "Python 3.10+ is required."; exit 1; fi

# 0. config.json from example
if [ ! -f "$BACKEND_DIR/config.json" ]; then
  cp "$BACKEND_DIR/config.example.json" "$BACKEND_DIR/config.json"
  green "  [config] Created backend/config.json from example (git-ignored)."
else
  green "  [config] Using existing backend/config.json."
fi

# 1. venv
if [ ! -d "$VENV_DIR" ]; then
  yellow "  [venv] Creating Python virtual environment..."
  "$PY" -m venv "$VENV_DIR"
else
  green "  [venv] Found existing venv."
fi
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# 2. python deps
yellow "  [pip] Installing backend dependencies..."
pip install -q -r "$BACKEND_DIR/requirements.txt"
green "  [pip] Ready."

# 3. node deps
if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
  yellow "  [npm] Installing frontend dependencies..."
  (cd "$FRONTEND_DIR" && npm install --silent)
fi
green "  [npm] Ready."

# 4. start backend
yellow "  [backend] Starting FastAPI on http://localhost:8000 ..."
(cd "$BACKEND_DIR" && "$VENV_DIR/bin/python" -m uvicorn main:app --host 0.0.0.0 --port 8000) &
BACKEND_PID=$!
green "  [backend] PID $BACKEND_PID"

# 5. start frontend
yellow "  [frontend] Starting Express on http://localhost:3000 ..."
(cd "$FRONTEND_DIR" && node server.js) &
FRONTEND_PID=$!
green "  [frontend] PID $FRONTEND_PID"

echo "$BACKEND_PID $FRONTEND_PID" > "$SCRIPT_DIR/.graphraider.pids"

# 6. wait + open browser
sleep 3
for _ in 1 2 3 4 5 6; do
  if curl -s -o /dev/null "http://localhost:8000/health"; then break; fi
  sleep 1
done
echo ""
cyan "  ---------------------------------------------------"
echo  "  UI        http://localhost:3000"
echo  "  Backend   http://localhost:8000"
cyan "  ---------------------------------------------------"
( command -v open >/dev/null && open "http://localhost:3000" ) || \
( command -v xdg-open >/dev/null && xdg-open "http://localhost:3000" ) || true

echo ""
echo "  Stop with ./kill.sh - or press Ctrl+C to stop both now."
trap 'kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0' INT
wait
