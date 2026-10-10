"""命令级拦截规则引擎（移植 ARTEX guard/intercept：allow/deny/ask 三态 + DB 可配 + 人工审批）。

- 规则存 pimeta.db `intercept_rules`（首次连接自动种子 21 条 ARTEX 内置规则；
  用户可启用/禁用/改模式/增删，每次检查直读库 = 热加载，不用重启）
- 检查点在 executor 工具执行前：扫命令/代码面工具的完整 args JSON
  （默认 bash/terminal/exec_command/python/sqlmap/sqlmap_exploit/nmap/nikto/http_request，
  HINSE_INTERCEPT_TOOLS 可覆盖）；submit_finding 等记录类工具不扫
  （证据文本里的命令不能误伤 finding 提交）
- first-match-wins（priority 降序）：
    deny  → 直接拦截，返回提示给 LLM（换个思路，别重试同命令）
    allow → 显式放行（优先级高于 deny，白名单语义）
    ask   → 进审批队列（intercept_decisions 表 status=pending），阻塞等待
            /api/intercept/{id}/decide 人工裁决；超时按 HINSE_INTERCEPT_ASK_TIMEOUT
            兜底为 deny；任务取消 → 该 ask 记 denied 并放行阻塞
- 审计：deny/allow 命中与审批结果都落 intercept_decisions（status=denied/allowed），
  GET /api/intercept/history 可查

配置（.env 热加载）：
  HINSE_INTERCEPT_ENABLED     默认 1
  HINSE_INTERCEPT_TOOLS       逗号分隔工具名，默认见 _DEFAULT_SCAN_TOOLS
  HINSE_INTERCEPT_ASK_TIMEOUT 秒，默认 300
"""
from __future__ import annotations

import asyncio
import json
import re
import sqlite3
from typing import Any, Dict, List, Optional

import agents.tools as _tools
from config import env as _cfg_env

_DEFAULT_SCAN_TOOLS = ("bash", "terminal", "exec_command", "python",
                       "sqlmap", "sqlmap_exploit", "nmap", "nikto", "http_request")

_RULES_TABLE = """CREATE TABLE IF NOT EXISTS intercept_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 50,
  pattern TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT 'deny',
  message TEXT,
  created_at TEXT
)"""

_DECISIONS_TABLE = """CREATE TABLE IF NOT EXISTS intercept_decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT,
  tool_name TEXT,
  args_json TEXT,
  rule_id INTEGER,
  rule_name TEXT,
  rule_action TEXT,
  message TEXT,
  status TEXT NOT NULL,
  decided_by TEXT,
  decided_at TEXT,
  created_at TEXT
)"""

# ARTEX 内置规则（db/db.go seedDefaultInterceptRules v1/v2/v3 全量移植；
# Go 正则与 Python 语法兼容，逐条验证过）。#20 数据外泄管道 ARTEX 默认禁用
# （对合法 CTF 反向 shell/数据管道误报），保留禁用。
_SEED_RULES: List[tuple] = [
    ("[内置] 递归强制删除 rm -rf", 100, "deny",
     r"(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)",
     "禁止执行递归强制删除（rm -rf / rm --recursive），可能永久损坏系统或靶机环境", True),
    ("[内置] 删除系统关键目录", 100, "deny",
     r"\brm\b[^\"'\n]{0,60}[\"'\s](/|/etc|/bin|/usr|/boot|/var|/lib|/sys|/proc|/dev|/sbin|/root)",
     "禁止删除系统关键路径", True),
    ("[内置] 磁盘格式化 mkfs", 100, "deny",
     r"\bmkfs\b", "禁止格式化磁盘（mkfs）", True),
    ("[内置] 覆写磁盘设备 dd", 100, "deny",
     r"\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]", "禁止使用 dd 覆写磁盘设备", True),
    ("[内置] Fork 炸弹", 100, "deny",
     r":\(\)\s*\{[^}]*:\|:", "禁止执行 Fork 炸弹", True),
    ("[内置] 关机 / 重启", 100, "deny",
     r"\b(?:shutdown|reboot|halt|poweroff|init\s+[06])\b", "禁止执行关机或重启命令", True),
    ("[内置] 杀死全部进程", 100, "deny",
     r"\bkill\s+-9\s+-1\b|\bkillall\s+-9\b", "禁止 kill -9 -1 或 killall -9（杀死所有进程）", True),
    ("[内置] 磁盘擦除 shred / wipe", 100, "deny",
     r"\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]", "禁止对磁盘设备执行 shred/wipe 擦除", True),
    ("[内置] 清空防火墙规则", 100, "deny",
     r"\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b", "禁止清空防火墙规则（iptables -F / nft flush）", True),
    ("[内置] 破坏性系统命令", 100, "deny",
     r"(?i)\b(rm\s+-rf\s+/|mkfs|dd\s+if=|:\(\)\s*\{|shutdown|reboot|>\s*/dev/sd)",
     "破坏性命令被拒绝（rm -rf / / mkfs / dd / fork bomb / 关机重启 / 覆写磁盘设备）", True),
    ("[内置] SQL DROP DATABASE / TABLE / SCHEMA", 90, "deny",
     r"(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b",
     "禁止执行 DROP 操作，可能不可逆地销毁数据库对象", True),
    ("[内置] SQL TRUNCATE", 90, "deny",
     r"(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w", "禁止执行 TRUNCATE，可能清空数据表所有数据", True),
    ("[内置] MongoDB drop / dropDatabase", 90, "deny",
     r"(?i)\.(?:dropDatabase|dropCollection|drop)\s*\(", "禁止执行 MongoDB drop 操作", True),
    ("[内置] Redis FLUSHALL / FLUSHDB", 90, "deny",
     r"(?i)\b(?:FLUSHALL|FLUSHDB)\b", "禁止执行 Redis FLUSHALL / FLUSHDB，可能清空全部缓存数据", True),
    ("[内置] curl / wget 发送 DELETE 请求", 80, "deny",
     r"(?i)\bcurl\b[^|\n&;\"]{0,300}(?:-X\s*DELETE|--request\s+DELETE|-XDELETE)|\bwget\b[^|\n&;\"]{0,300}--method[=\s]+DELETE",
     "禁止通过 curl/wget 发送 HTTP DELETE 请求，可能删除目标系统数据", True),
    ("[内置] Python HTTP 客户端 DELETE（requests/httpx/aiohttp）", 80, "deny",
     r"(?i)\b(?:requests|httpx|aiohttp|urllib\.request)\.delete\s*\(|session\.delete\s*\(|client\.delete\s*\(",
     "禁止使用 Python HTTP 客户端发送 DELETE 请求", True),
    ("[内置] 脚本中声明 HTTP DELETE 方法（JS/通用）", 80, "deny",
     r"(?i)axios\.delete\s*\(|method\s*[:=]\s*['\"]DELETE['\"]",
     "禁止在脚本中声明并发送 HTTP DELETE 请求", True),
    ("[内置] 批量清空 / 清除接口路径", 80, "deny",
     r"(?i)/(?:clear|wipe|flush|purge|truncate|drop|destroy|factory[-_]reset|reset[-_]all)(?:[/?#\"'\s]|$)",
     "禁止调用批量清空或销毁类接口（/clear /wipe /flush /purge 等）", True),
    ("[内置] 数据外泄管道", 80, "deny",
     r"(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))",
     "疑似数据外泄管道被拒绝（命令输出经 curl/wget/nc 外传）", False),
    ("[内置] 删除类接口路径", 80, "deny",
     r"(?i)/(?:(?:delete|remove|unlink|erase|destroy)[-\w]*|del)(?:[/?#\"'\s]|$)",
     "禁止调用删除类接口（/delete /remove /unlink /erase 等），不论使用哪种 HTTP 方法——"
     "多数应用的删除接口用 GET/POST 就能触发，同样会真实删除目标数据", True),
    ("[内置] HTTP 请求工具 DELETE method（JSON 参数）", 80, "deny",
     r"(?i)\"method\"\s*:\s*\"DELETE\"",
     "禁止通过 HTTP 请求工具发送 DELETE 方法", True),
]

_compiled_cache: Dict[str, Optional[re.Pattern]] = {}
_pending: Dict[int, asyncio.Future] = {}
_pending_lock = asyncio.Lock()


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_tools.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(_RULES_TABLE)
    conn.execute(_DECISIONS_TABLE)
    _seed_rules(conn)
    conn.commit()
    return conn


def _seed_rules(conn: sqlite3.Connection) -> None:
    """首次建表时灌入 ARTEX 内置规则；已有规则不覆盖（用户编辑永不被冲掉）。"""
    n = conn.execute("SELECT COUNT(*) FROM intercept_rules").fetchone()[0]
    if n:
        return
    ts = _now()
    conn.executemany(
        "INSERT INTO intercept_rules (name, enabled, priority, pattern, action, message, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        [(name, 1 if enabled else 0, prio, pattern, action, msg, ts)
         for name, prio, action, pattern, msg, enabled in _SEED_RULES])


def _enabled() -> bool:
    return _cfg_env("HINSE_INTERCEPT_ENABLED", "1") not in ("0", "false", "False", "")


def _scan_tools() -> set:
    raw = _cfg_env("HINSE_INTERCEPT_TOOLS", "")
    if raw:
        return {t.strip() for t in raw.split(",") if t.strip()}
    return set(_DEFAULT_SCAN_TOOLS)


def _ask_timeout() -> float:
    try:
        return max(1.0, float(_cfg_env("HINSE_INTERCEPT_ASK_TIMEOUT", "300")))
    except (TypeError, ValueError):
        return 300.0


def _compiled(pattern: str) -> Optional[re.Pattern]:
    pat = _compiled_cache.get(pattern, _MISSING)
    if pat is _MISSING:
        try:
            pat = re.compile(pattern)
        except re.error:
            pat = None
        _compiled_cache[pattern] = pat
    return pat


_MISSING = object()


def _load_rules() -> List[sqlite3.Row]:
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT * FROM intercept_rules WHERE enabled=1 ORDER BY priority DESC, id").fetchall()
    finally:
        conn.close()
    return rows


def _log_decided(task_id: str, tool_name: str, args_json: str, rule: Dict[str, Any],
                 status: str, decided_by: str) -> int:
    conn = _conn()
    try:
        cur = conn.execute(
            "INSERT INTO intercept_decisions (task_id, tool_name, args_json, rule_id, rule_name, "
            "rule_action, message, status, decided_by, decided_at, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (task_id, tool_name, args_json[:4000], rule.get("id"), rule.get("name"),
             rule.get("action"), rule.get("message"), status, decided_by, _now(), _now()))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def _create_pending(task_id: str, tool_name: str, args_json: str, rule: Dict[str, Any]) -> int:
    return _log_decided(task_id, tool_name, args_json, rule, "pending", "rule")


def _resolve_decision(decision_id: int, status: str, decided_by: str) -> None:
    conn = _conn()
    try:
        conn.execute(
            "UPDATE intercept_decisions SET status=?, decided_by=?, decided_at=? "
            "WHERE id=? AND status='pending'",
            (status, decided_by, _now(), decision_id))
        conn.commit()
    finally:
        conn.close()
    fut = _pending.get(decision_id)
    if fut is not None and not fut.done():
        fut.set_result(status)


async def _wait_decision(decision_id: int) -> str:
    """阻塞等待人工裁决；超时 → deny 兜底；任务取消 → 记 denied 并上抛取消。"""
    fut = asyncio.get_running_loop().create_future()
    async with _pending_lock:
        # 竞态修复（ARTEX 同款）：decide 可能在 INSERT 后、future 注册前到达，
        # 注册后重读库，防止裁决丢失
        conn = _conn()
        try:
            row = conn.execute(
                "SELECT status FROM intercept_decisions WHERE id=?", (decision_id,)).fetchone()
        finally:
            conn.close()
        if row is not None and row["status"] != "pending":
            return row["status"]
        _pending[decision_id] = fut
    try:
        return await asyncio.wait_for(fut, timeout=_ask_timeout())
    except asyncio.TimeoutError:
        _resolve_decision(decision_id, "denied", "timeout")
        print(f"[intercept] 审批 #{decision_id} 超时({ _ask_timeout():.0f}s) → deny 兜底", flush=True)
        return "denied"
    except asyncio.CancelledError:
        _resolve_decision(decision_id, "denied", "task-cancelled")
        raise
    finally:
        async with _pending_lock:
            _pending.pop(decision_id, None)


async def intercept_check(tool_name: str, args: Dict[str, Any], task_id: str) -> Optional[Dict[str, Any]]:
    """执行前检查：命中拦截规则返回"给 LLM 的阻断结果"，放行返回 None。"""
    if not _enabled() or tool_name not in _scan_tools():
        return None
    subject = json.dumps(args, ensure_ascii=False)
    for row in _load_rules():
        compiled = _compiled(row["pattern"])
        if compiled is None:
            continue  # 坏正则规则忽略（不阻塞工具调用）
        if not compiled.search(subject):
            continue
        rule = dict(row)
        action = rule["action"]
        msg = rule.get("message") or rule["name"]
        if action == "allow":
            _log_decided(task_id, tool_name, subject, rule, "allowed", "rule")
            return None
        if action == "deny":
            print(f"[intercept] DENY task={task_id} tool={tool_name} rule={rule['name']}", flush=True)
            _log_decided(task_id, tool_name, subject, rule, "denied", "rule")
            return {"error": f"平台安全管控拦截：{msg}（规则：{rule['name']}）。"
                             f"该命令被禁止执行，请换思路，不要重试同一命令。",
                    "intercepted": rule["name"]}
        if action == "ask":
            did = _create_pending(task_id, tool_name, subject, rule)
            print(f"[intercept] ASK task={task_id} tool={tool_name} rule={rule['name']} "
                  f"pending=#{did} 等待人工审批", flush=True)
            verdict = await _wait_decision(did)
            if verdict == "allowed":
                return None
            return {"error": f"平台安全管控审批未通过（{verdict}）：{msg}（规则：{rule['name']}）。"
                             f"该命令未被批准，请换思路，不要重试同一命令。",
                    "intercepted": rule["name"]}
        # 未知 action 视同放行（配置错误不应阻塞任务）
        return None
    return None


def decide_decision(decision_id: int, action: str, note: str = "") -> Optional[Dict[str, Any]]:
    """人工裁决（审批端点入口）：allow → allowed，deny → denied。返回裁决后的记录。"""
    if action not in ("allow", "deny"):
        raise ValueError("action must be allow or deny")
    status = "allowed" if action == "allow" else "denied"
    by = f"user{':' + note if note else ''}"[:200]
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT * FROM intercept_decisions WHERE id=?", (decision_id,)).fetchone()
        if row is None:
            return None
        if row["status"] != "pending":
            return dict(row)  # 已裁决过，幂等返回
        conn.execute(
            "UPDATE intercept_decisions SET status=?, decided_by=?, decided_at=? WHERE id=?",
            (status, by, _now(), decision_id))
        conn.commit()
    finally:
        conn.close()
    fut = _pending.get(decision_id)
    if fut is not None and not fut.done():
        fut.set_result(status)
    else:
        print(f"[intercept] 审批 #{decision_id} 无等待者（进程重启/已超时），仅落库", flush=True)
    return {"id": decision_id, "status": status, "decided_by": by}


def list_pending(task_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        if task_id:
            rows = conn.execute(
                "SELECT * FROM intercept_decisions WHERE status='pending' AND task_id=? ORDER BY id",
                (task_id,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM intercept_decisions WHERE status='pending' ORDER BY id").fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def list_history(limit: int = 50, task_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        if task_id:
            rows = conn.execute(
                "SELECT * FROM intercept_decisions WHERE task_id=? AND status!='pending' "
                "ORDER BY id DESC LIMIT ?", (task_id, limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM intercept_decisions WHERE status!='pending' "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def list_rules() -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        rows = conn.execute("SELECT * FROM intercept_rules ORDER BY priority DESC, id").fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def upsert_rule(rule_id: Optional[int], name: str, pattern: str, action: str,
                priority: int = 50, enabled: bool = True, message: str = "") -> int:
    if action not in ("deny", "ask", "allow"):
        raise ValueError("action must be deny, ask or allow")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name or ""):
        # 规则名允许中文，只拦注入特征（引号/分号）
        if any(ch in (name or "") for ch in ("'", '"', ";", "--")):
            raise ValueError("invalid rule name")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}")
    conn = _conn()
    try:
        ts = _now()
        if rule_id:
            cur = conn.execute(
                "UPDATE intercept_rules SET name=?, pattern=?, action=?, priority=?, "
                "enabled=?, message=? WHERE id=?",
                (name, pattern, action, int(priority), 1 if enabled else 0, message, rule_id))
            if cur.rowcount == 0:
                return 0
            conn.commit()
            return rule_id
        cur = conn.execute(
            "INSERT INTO intercept_rules (name, enabled, priority, pattern, action, message, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (name, 1 if enabled else 0, int(priority), pattern, action, message, ts))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def delete_rule(rule_id: int) -> bool:
    conn = _conn()
    try:
        cur = conn.execute("DELETE FROM intercept_rules WHERE id=?", (rule_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


__all__ = [
    "intercept_check",
    "decide_decision",
    "list_pending",
    "list_history",
    "list_rules",
    "upsert_rule",
    "delete_rule",
]
