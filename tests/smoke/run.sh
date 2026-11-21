#!/bin/sh
set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NTSC="${NTSC:-ntsc}"
PYTHON="${PYTHON:-python3}"
PORT="${PORT:-8765}"

cd "$DIR"
"$NTSC" build >/dev/null

"$PYTHON" -u echo_server.py >/tmp/ws_echo_server_smoke.log 2>&1 &
SERVER_PID=$!

cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# wait for server readiness
i=0
while [ $i -lt 50 ]; do
  if grep -q "READY $PORT" /tmp/ws_echo_server_smoke.log 2>/dev/null; then
    break
  fi
  sleep 0.1
  i=$((i + 1))
done

if ! grep -q "READY $PORT" /tmp/ws_echo_server_smoke.log 2>/dev/null; then
  echo "echo server failed to start" >&2
  cat /tmp/ws_echo_server_smoke.log >&2 || true
  exit 1
fi

./build/debug/ws_smoke
