#!/usr/bin/env bash
# kill.sh - stop GraphRaider (macOS / Linux)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "  GraphRaider - stopping services"

# Prefer recorded PIDs, fall back to port lookup.
if [ -f "$SCRIPT_DIR/.graphraider.pids" ]; then
  for pid in $(cat "$SCRIPT_DIR/.graphraider.pids"); do
    kill "$pid" 2>/dev/null && echo "  killed PID $pid" || true
  done
  rm -f "$SCRIPT_DIR/.graphraider.pids"
fi

for port in 8000 3000; do
  pids="$(lsof -ti tcp:"$port" 2>/dev/null || true)"
  for pid in $pids; do kill -9 "$pid" 2>/dev/null && echo "  killed PID $pid on :$port" || true; done
done
echo "  Done."
echo ""
