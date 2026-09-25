#!/usr/bin/env bash
# RED-KB 进程守护(轻量自愈):若 RED-KB 未在监听则重启。
# 用法: 放入 cron (每1分钟) 或作为独立循环:
#   * * * * * /path/to/platform/guard_redkb.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8001
URL="${REDKB_URL:-http://127.0.0.1:$PORT/health}"
if curl -sf --max-time 3 "$URL" >/dev/null 2>&1; then
  exit 0   # 正常,无需处理
fi
# 未响应 -> 重启
echo "$(date) RED-KB down, restarting" >> /tmp/redkb-guard.log
pkill -f "redkb.app" 2>/dev/null
sleep 1
setsid "$SCRIPT_DIR/start_redkb.sh" >/dev/null 2>&1 < /dev/null &
disown
exit 0
