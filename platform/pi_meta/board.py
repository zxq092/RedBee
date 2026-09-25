"""漏洞板 (Findings Board): 并行渗透的实时协调状态。

一张 findings 表(与 sessions/messages/reports 同库 pimeta.db),同一 task 的所有
并行 agent 共享:

    found ──(另一 agent 复现 PoC 通过, 阈值=1)──▶ confirmed
    found ──(复现失败)─────────────────────────▶ false_positive

跳过语义 = 跳过"重复利用同一漏洞", 不跳过整个模块(其他参数/注入点仍可打)。
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional

from .sessions import _connect, utcnow

_SCHEMA = """CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  target TEXT NOT NULL,
  dedup_key TEXT NOT NULL,
  vuln_class TEXT,
  title TEXT,
  location TEXT,
  poc TEXT,
  evidence TEXT,
  severity TEXT,
  status TEXT NOT NULL DEFAULT 'found',
  found_by TEXT,
  confirmed_by TEXT,
  created_at TEXT,
  confirmed_at TEXT,
  UNIQUE (task_id, dedup_key)
)"""

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _conn() -> sqlite3.Connection:
    conn = _connect()
    conn.execute(_SCHEMA)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}
    for col in ("confirmed_by", "confirmed_at"):
        if col not in cols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT")
    conn.commit()
    return conn


def dedup_key(f: Dict[str, Any]) -> str:
    """去重键, 与 report._dedup_key 同语义: 归一化 title@location。"""
    title = str(f.get("title", "")).strip().lower()
    loc = str(f.get("asset") or f.get("location") or "").strip().lower()
    return f"{title}@{loc}" if loc else title


def post(task_id: str, target: str, f: Dict[str, Any], found_by: str,
         status: str = "found") -> Optional[int]:
    """贴一条发现。新漏洞返回 id; 重复(同 task 同 dedup_key)返回 None 并补全 poc/evidence。"""
    key = dedup_key(f)
    poc = str(f.get("poc") or f.get("method") or "")[:2000]
    ev = str(f.get("evidence") or "")[:2000]
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT id FROM findings WHERE task_id=? AND dedup_key=?",
            (task_id, key)).fetchone()
        if existing:
            conn.execute(
                "UPDATE findings SET poc=COALESCE(NULLIF(poc,''),?), "
                "evidence=COALESCE(NULLIF(evidence,''),?) WHERE task_id=? AND dedup_key=?",
                (poc, ev, task_id, key))
            conn.commit()
            return None
        cur = conn.execute(
            "INSERT INTO findings "
            "(task_id,target,dedup_key,vuln_class,title,location,poc,evidence,severity,status,found_by,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (task_id, target, key,
             str(f.get("vuln_class") or f.get("technique") or "")[:60],
             str(f.get("title", ""))[:200],
             str(f.get("asset") or f.get("location") or "")[:300],
             poc, ev,
             str(f.get("severity", "medium")).lower()[:20],
             status, found_by, utcnow()))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def confirmed_brief(task_id: str) -> str:
    """已确认清单, 拼进派发 prompt 让其他 agent 跳过。无则返回空串。"""
    conn = _conn()
    rows = conn.execute(
        "SELECT severity, title, location FROM findings "
        "WHERE task_id=? AND status='confirmed' ORDER BY id", (task_id,)).fetchall()
    conn.close()
    if not rows:
        return ""
    lines = "\n".join(f"- [{r[0]}] {r[1]} @ {r[2] or '(n/a)'}" for r in rows)
    return (
        "CONFIRMED findings (already exploited AND independently verified by another agent.\n"
        "Do NOT re-exploit or re-report these specific vulns — spend effort on OTHER "
        "attack surface; other parameters/endpoints of the same module are still fair game):\n"
        + lines
    )


def unconfirmed_high(task_id: str) -> List[Dict[str, Any]]:
    """已贴板但未确认、且严重度达到强制复现阈值(high/critical)的发现。"""
    conn = _conn()
    rows = conn.execute(
        "SELECT id,vuln_class,title,location,poc,evidence,severity,found_by "
        "FROM findings WHERE task_id=? AND status='found' ORDER BY id", (task_id,)).fetchall()
    conn.close()
    out = []
    for r in rows:
        if SEV_ORDER.get(str(r[6]).lower(), 0) >= SEV_ORDER["high"]:
            out.append({"id": r[0], "vuln_class": r[1], "title": r[2], "location": r[3],
                        "poc": r[4] or "", "evidence": r[5] or "", "severity": r[6],
                        "found_by": r[7]})
    return out


def mark(task_id: str, fid: int, status: str, confirmed_by: Optional[str] = None) -> None:
    """状态流转: confirmed(带确认者) / false_positive / found(回退)。"""
    conn = _conn()
    if status == "confirmed":
        conn.execute(
            "UPDATE findings SET status='confirmed', confirmed_by=?, confirmed_at=? "
            "WHERE task_id=? AND id=?", (confirmed_by, utcnow(), task_id, fid))
    else:
        conn.execute("UPDATE findings SET status=? WHERE task_id=? AND id=?",
                     (status, task_id, fid))
    conn.commit()
    conn.close()


def get_finding(task_id: str, fid: int) -> Optional[Dict[str, Any]]:
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT id,target,vuln_class,title,location,poc,evidence,severity,status,"
            "found_by,confirmed_by,created_at,confirmed_at FROM findings "
            "WHERE task_id=? AND id=?", (task_id, fid)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    cols = ["id", "target", "vuln_class", "title", "location", "poc", "evidence",
            "severity", "status", "found_by", "confirmed_by", "created_at", "confirmed_at"]
    return dict(zip(cols, row))


def all_findings(task_id: str) -> List[Dict[str, Any]]:
    conn = _conn()
    rows = conn.execute(
        "SELECT id,target,vuln_class,title,location,poc,evidence,severity,status,"
        "found_by,confirmed_by,created_at,confirmed_at FROM findings "
        "WHERE task_id=? ORDER BY id", (task_id,)).fetchall()
    conn.close()
    cols = ["id", "target", "vuln_class", "title", "location", "poc", "evidence",
            "severity", "status", "found_by", "confirmed_by", "created_at", "confirmed_at"]
    return [dict(zip(cols, r)) for r in rows]
