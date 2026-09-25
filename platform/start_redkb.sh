#!/usr/bin/env bash
# Robust detached RED-KB runner
cd "$(dirname "$0")" || exit 1
exec setsid python3 -m uvicorn redkb.app:app --host 0.0.0.0 --port 8001 >> /tmp/redkb.log 2>&1 < /dev/null
