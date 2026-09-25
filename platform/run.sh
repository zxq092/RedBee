#!/usr/bin/env bash
# Launch the RED-KB service and the Pi Meta gateway.
set -e
cd "$(dirname "$0")"

echo "==> Seeding RED-KB ..."
python3 -m redkb.seed

echo "==> Starting RED-KB on :8001 ..."
python3 -m uvicorn redkb.app:app --host 127.0.0.1 --port 8001 > /tmp/redkb.log 2>&1 &
REDKB_PID=$!

echo "==> Starting Pi Meta on :8000 ..."
python3 -m uvicorn pi_meta.app:app --host 127.0.0.1 --port 8000 --timeout-graceful-shutdown 5 > /tmp/pimeta.log 2>&1 &
PIMETA_PID=$!

echo "==> Ready"
echo "  Web UI:  http://127.0.0.1:8000"
echo "  RED-KB:  http://127.0.0.1:8001"
echo "  Ctrl-C to stop."
trap 'kill $REDKB_PID $PIMETA_PID 2>/dev/null' EXIT INT TERM
wait
