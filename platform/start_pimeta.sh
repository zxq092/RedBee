#!/usr/bin/env bash
# detached Pi Meta gateway
# --timeout-graceful-shutdown 5: 防 SSE(/stream)长连接卡死优雅停机(kill 不掉)
cd "$(dirname "$0")" || exit 1
exec setsid python3 -m uvicorn pi_meta.app:app --host 0.0.0.0 --port 8000 --timeout-graceful-shutdown 5 >> /tmp/pimeta.log 2>&1 < /dev/null
