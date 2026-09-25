"""Per-task 执行日志（结构化、可下载、重启不丢）。

一行 = 一个事件：派发/相位/LLM 调用/工具调用/发现/失败/指令/停止。
写入点分散在 executor/orchestrator_v2/app（低频，逐条落库无压力）。
前端"下载日志 (.txt)"从 query() 重建人类可读时间线。
"""
from __future__ import annotations

import threading
from typing import Any, Dict, List

from .sessions import _connect, utcnow

_SCHEMA = """CREATE TABLE IF NOT EXISTS task_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  module TEXT,
  kind TEXT NOT NULL,
  detail TEXT
)"""
_INDEX = "CREATE INDEX IF NOT EXISTS idx_task_logs_task ON task_logs(task_id, id)"

# 表只建一次（进程内幂等）
_ensured = False
_lock = threading.Lock()


def _conn():
    global _ensured
    conn = _connect()
    if not _ensured:
        with _lock:
            if not _ensured:
                conn.execute(_SCHEMA)
                conn.execute(_INDEX)
                conn.commit()
                _ensured = True
    return conn


def log(task_id: str, kind: str, detail: str, module: str = "") -> None:
    """记一行执行日志。kind: dispatch/phase/llm/tool/finding/error/steer/stop/note。
    失败静默——日志不能反过来搞挂任务。"""
    if not task_id or not kind:
        return
    try:
        conn = _conn()
        conn.execute(
            "INSERT INTO task_logs (task_id, ts, module, kind, detail) VALUES (?,?,?,?,?)",
            (task_id, utcnow(), module or "", kind, str(detail)[:2000]))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[task-logs] write error: {type(e).__name__}: {e}", flush=True)


def query(task_id: str) -> List[Dict[str, Any]]:
    """按时间序返回该任务全部日志行。"""
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT ts, module, kind, detail FROM task_logs WHERE task_id=? ORDER BY id",
            (task_id,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def count_kinds(task_id: str, kinds: tuple) -> int:
    """统计某几类事件行数（左栏进度用：module_done 计数等）。"""
    if not task_id or not kinds:
        return 0
    conn = _conn()
    try:
        marks = ",".join("?" * len(kinds))
        r = conn.execute(
            f"SELECT COUNT(*) FROM task_logs WHERE task_id=? AND kind IN ({marks})",
            (task_id, *kinds)).fetchone()
    finally:
        conn.close()
    return int(r[0]) if r else 0


def render_text(task_id: str, meta: Dict[str, Any] | None = None) -> str:
    """重建人类可读时间线（下载 .txt 用）。历史任务无日志时给说明头。"""
    meta = meta or {}
    lines = [
        f"# 执行日志  task={task_id}",
        f"# target={meta.get('target', '')}  target_id={meta.get('target_id', '')}",
        f"# status={meta.get('status', '')}  model={meta.get('runtime_model') or meta.get('model', '')}",
        f"# modules={','.join(meta.get('assigned_modules') or [])}",
        "",
    ]
    rows = query(task_id)
    if not rows:
        lines.append("(该任务无详细日志——日志采集覆盖其后的新任务；结构化结果见漏洞板/报告)")
        return "\n".join(lines) + "\n"
    for r in rows:
        ts = str(r.get("ts", ""))[:19].replace("T", " ")
        mod = f"[{r['module']}] " if r.get("module") else ""
        lines.append(f"[{ts}] {mod}{r['kind']:>9}  {r.get('detail', '')}")
    return "\n".join(lines) + "\n"
