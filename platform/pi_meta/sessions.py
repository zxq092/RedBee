"""Platform-level (user) memory: session + chat history + task reports (doc 4.1)."""

import sqlite3
import json
import os
import uuid
from typing import Any, Dict, List

DATA_DIR = os.environ.get("PIMETA_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "data"))
DB_PATH = os.environ.get("PIMETA_DB", os.path.join(DATA_DIR, "pimeta.db"))


def _connect():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY, title TEXT, created_at TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, role TEXT,
        content TEXT, created_at TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, task TEXT,
        target TEXT, model TEXT, report_md TEXT, meta TEXT, created_at TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS task_metadata (
        task_id TEXT PRIMARY KEY, target TEXT, target_id TEXT, model TEXT,
        agents TEXT, assigned_modules TEXT, status TEXT, created_at TEXT,
        updated_at TEXT)""")
    runtime_columns = {
        "runtime_model": "TEXT",
        "runtime_id": "TEXT",
        "degraded_from": "TEXT",
        "degraded_chain": "TEXT",
        "runtime_error_code": "TEXT",
        "runtime_error_summary": "TEXT",
        "model_override": "TEXT",
        "session_id": "TEXT",
        # 原始任务文本（全局任务视图展示 + 重跑按钮原样重派）
        "task_text": "TEXT",
    }
    existing = {row[1] for row in cur.execute("PRAGMA table_info(task_metadata)").fetchall()}
    for name, kind in runtime_columns.items():
        if name not in existing:
            cur.execute(f"ALTER TABLE task_metadata ADD COLUMN {name} {kind}")
    conn.commit()
    return conn


def utcnow():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def create_session(title=None):
    conn = _connect()
    sid = uuid.uuid4().hex[:12]
    cur = conn.cursor()
    now = utcnow()
    if not title or not title.strip() or title == "新会话":
        from datetime import datetime
        cur.execute("INSERT INTO sessions VALUES (?,?,?)", (sid, f"新会话 {datetime.now().strftime('%m-%d %H:%M')}", now))
    else:
        cur.execute("INSERT INTO sessions VALUES (?,?,?)", (sid, title.strip(), now))
    conn.commit()
    conn.close()
    return sid


def ensure_session(sid, title=""):
    """确保指定 sid 的会话存在（不存在则创建）。用于客户端自带 session_id 的场景。"""
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT id FROM sessions WHERE id=?", (sid,))
    if cur.fetchone() is None:
        cur.execute("INSERT OR IGNORE INTO sessions VALUES (?,?,?)",
                    (sid, title or sid, utcnow()))
        conn.commit()
    conn.close()
    return sid


def autotitle_if_default(sid, title):
    """会话名仍是默认自动名（新会话 …）时改成给定标题（首任务自动命名，治"新会话 09-21 15:48 是什么"）。"""
    title = (title or "").strip()
    if not title:
        return
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT title FROM sessions WHERE id=?", (sid,))
    row = cur.fetchone()
    if row and (row[0] or "").startswith("新会话"):
        cur.execute("UPDATE sessions SET title=? WHERE id=?", (title[:40], sid))
        conn.commit()
    conn.close()


def has_running_task(session_id: str) -> bool:
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM task_metadata WHERE session_id=? AND status='running'", (session_id,))
    n = cur.fetchone()[0]
    conn.close()
    return n > 0


def delete_session(sid):
    """删除会话。该会话有运行中任务时拒删（返回 False，防孤儿任务）。"""
    if has_running_task(sid):
        return False
    conn = _connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM messages WHERE session_id=?", (sid,))
    cur.execute("DELETE FROM reports WHERE session_id=?", (sid,))
    cur.execute("DELETE FROM sessions WHERE id=?", (sid,))
    conn.commit()
    conn.close()
    return True


def rename_session(sid, title):
    title = (title or "").strip()
    if not title:
        return False
    conn = _connect()
    cur = conn.cursor()
    cur.execute("UPDATE sessions SET title=? WHERE id=?", (title, sid))
    conn.commit()
    changed = cur.rowcount > 0
    conn.close()
    return changed


def list_sessions():
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT id, title, created_at FROM sessions ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "title": r[1], "created_at": r[2]} for r in rows]


def get_messages(session_id):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT role, content, created_at FROM messages WHERE session_id=? ORDER BY id", (session_id,))
    rows = cur.fetchall()
    conn.close()
    return [{"role": r[0], "content": r[1], "created_at": r[2]} for r in rows]


def add_message(session_id, role, content):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("INSERT INTO messages (session_id, role, content, created_at) VALUES (?,?,?,?)",
                (session_id, role, content, utcnow()))
    conn.commit()
    conn.close()


def save_report(session_id, task, target, model, report_md, meta):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("INSERT INTO reports (session_id, task, target, model, report_md, meta, created_at) VALUES (?,?,?,?,?,?,?)",
                (session_id, task, target, model, report_md, json.dumps(meta, ensure_ascii=False), utcnow()))
    conn.commit()
    conn.close()


def save_task_metadata(task_id: str, target: str = "", target_id: str = "", model: str = "",
                        agents: List[str] = None, assigned_modules: List[str] = None,
                        status: str = "running", runtime_model: str = "", runtime_id: str = "",
                        degraded_from: str = "", degraded_chain: str = "",
                        runtime_error_code: str = "", runtime_error_summary: str = "",
                        model_override: str = "", session_id: str = "", task_text: str = "") -> None:
    conn = _connect()
    cur = conn.cursor()
    now = utcnow()
    # task_text 只在首次 INSERT 时写入，UPDATE SET 不含它 → 后续状态更新不覆盖原始文本
    cur.execute("""INSERT INTO task_metadata
        (task_id,target,target_id,model,agents,assigned_modules,status,created_at,updated_at,
         runtime_model,runtime_id,degraded_from,degraded_chain,runtime_error_code,
         runtime_error_summary,model_override,session_id,task_text)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(task_id) DO UPDATE SET
        target=excluded.target, target_id=excluded.target_id, model=excluded.model,
        agents=excluded.agents, assigned_modules=excluded.assigned_modules,
        status=excluded.status, runtime_model=excluded.runtime_model,
        runtime_id=excluded.runtime_id, degraded_from=excluded.degraded_from,
        degraded_chain=excluded.degraded_chain, runtime_error_code=excluded.runtime_error_code,
        runtime_error_summary=excluded.runtime_error_summary, model_override=excluded.model_override,
        session_id=COALESCE(NULLIF(excluded.session_id,''), task_metadata.session_id),
        updated_at=excluded.updated_at""",
        (task_id, target, target_id, model,
         json.dumps(agents or [], ensure_ascii=False),
         json.dumps(assigned_modules or [], ensure_ascii=False), status, now, now,
         runtime_model, runtime_id, degraded_from, degraded_chain,
         runtime_error_code, runtime_error_summary, model_override, session_id, task_text))
    conn.commit()
    conn.close()


def get_task_metadata(task_id: str) -> Dict[str, Any]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT task_id,target,target_id,model,agents,assigned_modules,status,created_at,updated_at,"
            "runtime_model,runtime_id,degraded_from,degraded_chain,runtime_error_code,"
            "runtime_error_summary,model_override,session_id,task_text FROM task_metadata WHERE task_id=?", (task_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return {}
    out = dict(row)
    for key in ("agents", "assigned_modules"):
        try:
            out[key] = json.loads(out[key] or "[]")
        except Exception:
            out[key] = []
    return out


def list_tasks(status: str = "", limit: int = 200) -> List[Dict[str, Any]]:
    """任务列表（task_metadata）。status 过滤：running/done/cancelled/runtime_error/..."""
    conn = _connect()
    cur = conn.cursor()
    q = ("SELECT task_id, session_id, target, target_id, model, status, created_at, updated_at, "
         "agents, assigned_modules, runtime_error_summary, task_text FROM task_metadata")
    args: list = []
    if status:
        q += " WHERE status=?"
        args.append(status)
    q += " ORDER BY created_at DESC LIMIT ?"
    args.append(limit)
    cur.execute(q, args)
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        t = {"task_id": r[0], "session_id": r[1] or "", "target": r[2], "target_id": r[3],
             "model": r[4], "status": r[5], "created_at": r[6], "updated_at": r[7],
             "runtime_error_summary": r[10] or "", "task_text": r[11] or ""}
        for key, raw in (("agents", r[8]), ("assigned_modules", r[9])):
            try:
                t[key] = json.loads(raw or "[]")
            except Exception:
                t[key] = []
        out.append(t)
    return out


def get_reports(session_id):
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT id, task, target, model, report_md, created_at FROM reports WHERE session_id=? ORDER BY id", (session_id,))
    rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "task": r[1], "target": r[2], "model": r[3], "report_md": r[4], "created_at": r[5]} for r in rows]
