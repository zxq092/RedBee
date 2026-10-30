"""自研渗透智能体执行器 — 基于 tools/ TOOL_REGISTRY 的 ReAct 循环。

执行器不发明工具，只调度注册表中的工具。
工具调用走 OpenAI function calling 标准格式（tools 参数 + tool_calls 结构化返回）。
"""
from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import sqlite3
import time
import uuid
from typing import Any, AsyncIterator, Dict, List, Optional

from config import PIMETA_DB_PATH, DATA_DIR, env as cfg_env


from pi_meta.model_runtime import (
    AgentResult,
    ModelRuntimeError,
    ResolvedRuntime,
    RuntimeClient,
    coerce_resolved_runtime,
)
from pi_meta.task_logs import log as _tlog

from .tools import (
    TOOL_REGISTRY, _conn, get_tool, list_tools, PLAYBOOKS, ToolDef,
    get_skill_content, resolve_skill_name, resolve_target_id,
)
from .intercept import intercept_check

from redkb.case_schema import (
    CaseSnapshot, CoverageSnapshot, FindingSnapshot, ProvenanceSnapshot,
    ToolCallSnapshot, TrajectorySnapshot,
)
from redkb.governance import hash_text, sanitize_text
from redkb.store import add_case_evidence, submit_case

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


_load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
MAX_TURNS = int(os.environ.get("HINSE_MAX_TURNS", "60"))
DB_PATH = PIMETA_DB_PATH
KALI_IMAGE = os.environ.get("HINSE_DOCKER_IMAGE", "redbee-kali:local")


def _max_turns(agent) -> int:
    """单 agent 轮次上限：实例覆盖 > .env 热读（改 .env 即时生效）。"""
    v = getattr(agent, "MAX_TURNS", None)
    return int(v) if v else int(cfg_env("HINSE_MAX_TURNS", "60"))


def _kali_image() -> str:
    return cfg_env("HINSE_DOCKER_IMAGE", "redbee-kali:local")

# ---------------------------------------------------------------------------
# 渗透核心工具使用手册（注入 system prompt，让模型真正"会用"工具而不是靠猜）
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 工具门控（skill-gated tools，借 ARTEX skill-gated MCP：省工具面 token）
#
# 60 工具全量 schema ≈ 19K chars ≈ 每轮 7-9K token 固定开销（tools 参数每轮重发，
# 40 轮 child ≈ 30 万 token 纯工具面）。分阶段门控：
# - 核心集（执行器/KB/记录/todo/note/文件操作）常驻所有 agent
# - 专业工具按角色自动解锁（module）或运行时 load_skill 解锁（下一轮生效）
# - 遗留工具（pentagi/strix 存储族等）默认不进 agent 工具面（registry 保留）
# 实测（2026-10-10）：核心 34 工具 ≈ 10.5K chars，省 ~45% 固定面。
# ---------------------------------------------------------------------------

# 不进 agent 工具面的专业/遗留工具（解锁键见 TOOL_UNLOCK_MAP；无解锁键的永不可见）
GATED_TOOLS: set = {
    # 侦察族 → skill "recon"/"web2-recon"
    "nmap", "nikto", "fofa_search", "zoomeye_search", "list_sitemap",
    # SQLi 确定性执行器 → skill "sql-injection"
    "sqlmap", "sqlmap_exploit",
    # 浏览器 → skill "agent_browser"
    "browser",
    # 程序级利用（pwn）→ skill "binary-exploitation"
    "native_info", "native_gdb", "native_run", "native_interact", "native_pwn", "native_analyze", "native_source",
    # 白盒 → skill "source-aware-whitebox"
    "search_code", "amend_threat_model", "apply_patch",
    # 报告族 → skill "report-writing"
    "create_vulnerability_report", "list_reports",
    # 遗留（pentagi/strix 存储与规划族，当前流程代码级替代，不给 agent）
    "store_answer", "store_code", "store_guide", "search_guide", "search_answer",
    "search_in_memory", "advice", "ask", "ask_user",
    "subtask_list", "subtask_patch", "finish_scan", "report_result",
}

# skill 名 → 解锁的工具集（load_skill 命中或 module 聚焦 skill 命中时生效）
TOOL_UNLOCK_MAP: Dict[str, set] = {
    "sql-injection": {"sqlmap", "sqlmap_exploit"},
    "sqlmap": {"sqlmap", "sqlmap_exploit"},
    "hunt-sqli": {"sqlmap", "sqlmap_exploit"},
    "recon": {"nmap", "nikto", "fofa_search", "zoomeye_search", "list_sitemap"},
    "web2-recon": {"nmap", "nikto", "fofa_search", "zoomeye_search", "list_sitemap"},
    "recon-scope-triage": {"nmap", "nikto", "fofa_search", "zoomeye_search", "list_sitemap"},
    "agent_browser": {"browser"},
    "source-aware-whitebox": {"search_code", "amend_threat_model", "apply_patch"},
    "pre-recon-code": {"search_code", "amend_threat_model", "apply_patch"},
    "binary-exploitation": {"native_info", "native_gdb", "native_run", "native_interact",
                            "native_pwn", "native_analyze", "native_source"},
    "report-writing": {"create_vulnerability_report", "list_reports"},
    "report-executive": {"create_vulnerability_report", "list_reports"},
    "bugcrowd-reporting": {"create_vulnerability_report", "list_reports"},
}

# 模块 → 额外解锁键（"generic"=pre-recon/recon 任务级 agent，侦察工具从第 1 轮可用；
# 其余模块走 resolve_skill_name(module) 的聚焦 skill 自动解锁，如 sqli→sql-injection）
_MODULE_AUTO_UNLOCK: Dict[str, List[str]] = {
    "generic": ["recon"],
}


CORE_TOOL_MANUAL = """
=== TOOL MANUAL — HOW TO USE THE CORE TOOLS (READ BEFORE TESTING) ===
You have many tools. Below is how to CORRECTLY use the ones that matter for a real pentest. Ignoring this = guessing and failing.

=== TOOLSET (phased) ===
Your function tool list is loaded per role. Specialist tools are LOCKED until a matching skill is loaded
(load_skill) — they appear in your tool list from the NEXT turn:
- load_skill('sql-injection')  -> sqlmap, sqlmap_exploit   (deterministic SQLi detect + dump)
- load_skill('recon')          -> nmap, nikto, fofa_search, zoomeye_search, list_sitemap
- load_skill('agent_browser')  -> browser                  (headless; JS-rendered pages only)
- load_skill('source-aware-whitebox') -> search_code, amend_threat_model, apply_patch
- load_skill('report-writing') -> create_vulnerability_report, list_reports
If a tool you need is NOT in your current tool list, load the matching skill first — do NOT invent calls for missing tools.

1) http_request(method="GET", url, params?, headers?, body?, cookies?)
    - WHEN: fetch any page/endpoint, send requests to the target, capture evidence/responses.
    - RETURNS: {url, method, status, headers, text(<=8000 chars), history(redirects)}.
    - PITFALL: text is TRUNCATED at 8000 chars. For the tail, use a narrower request or params.
     - AUTH: to test an authenticated target, FIRST log in: (a) GET the login page, extract any CSRF/user_token hidden field;
       (b) POST credentials (+ token) to get a session; (c) capture the session cookie(s) from the response (Set-Cookie / your
       known cookie values); (d) pass them back as cookies="PHPSESSID=..;security=.." on EVERY authenticated request and to sqlmap.
       http_request/sqlmap do NOT keep sessions — you must carry cookies yourself each call.
       DO NOT use the browser tool to log in — it is STATELESS (each call regenerates the CSRF token, so the session never
       sticks and you will loop forever). Use http_request (or bash+curl with a -c/-b cookie jar) for login.

2) SQLi — TWO-STEP DETERMINISTIC FLOW (do NOT hand-write payloads) [sql-injection role; otherwise load_skill('sql-injection') first]:
     (a) sqlmap(url, params?, cookies?)  <- 4-vector DETECTOR (fast, host-side)
         - WHEN: check if a param is SQL-injectable (error / boolean / UNION / time).
         - AUTH target: pass cookies="k1=v1;k2=v2" (login first) or you test the login page, not the real query.
         - RETURNS: {injectable_params:[...]}.
     (b) sqlmap_exploit(url, cookies?, param?)  <- REAL sqlmap in the Kali sandbox: enumerates DBs/tables and DUMPS rows (DETERMINISTIC)
         - WHEN: AFTER (a) confirms an injectable param. One call returns {databases, db, tables, dump, evidence}.
         - It DUMPS the actual data for you — do NOT craft UNION/error payloads by hand. Use the dumped rows as submit_finding evidence.
     - PASS the full URL carrying the injectable value to BOTH, e.g. ".../sqli/?id=1&Submit=Submit".

3) kb_query(query, tags?, limit?)  <- RED-KB knowledge base (PROVEN PoCs & techniques)
    - WHEN: ALWAYS query KB before/instead of reinventing. It contains de-identified working techniques + PoCs.
    - PHRASE "query" by the FEATURE you found (e.g. "parameter reflected into DB query"), NOT the target name.
    - RETURNS: {results: [...]}.
    - USE its technique/PoC -> apply via http_request/sqlmap.

4) submit_finding(title, poc, evidence, asset?, severity?, vuln_class?, confidence*, counterevidence*)
    - WHEN: a vuln is CONFIRMED. Call it THE MOMENT you have a working PoC (a single proof = confirmed).
    - poc = the exact request/payload that proves it; evidence = the response/data that confirms it. NEVER report without a concrete PoC.
    - RETURNS: {accepted, id} (tells you if duplicate).
    - RULE: RECORD FIRST, deepen later. Don't hoard findings.

5) record_coverage(surface, risk_area, outcome, evidence?)
    - WHEN: after you touch any surface, record the HONEST outcome:
      reported / no_issue_found / ruled_out(REQUIRES evidence) / not_applicable / needs_follow_up.
    - An unrecorded surface is "unexamined", NOT "clean".

6) poc_verify(url, payload, method?, baseline?)
    - WHEN: verify whether payload changes behavior vs a baseline (diff-based confirm).
    - RETURNS: {baseline, poc_response, diff, verified}.

7) browser(url, action, selector?, value?) [locked; load_skill('agent_browser') to unlock]
    - WHEN: need JS-rendered pages, XSS execution proof, or auth flows (click/fill).
    - actions: navigate / screenshot / click / fill / eval.
    - PITFALL: EACH call launches a new headless chromium (slow). Use only for what http_request can't do.

GOLDEN RULES:
- QUERY KB FIRST (kb_query): the KB has proven techniques/PoCs — reuse, don't reinvent.
- CONFIRM THEN RECORD: one working proof -> submit_finding + record_coverage in the SAME turn.
- Record immediately; never sit on a confirmed finding; never report without a concrete PoC.
6) NOT sure how to use a tool? Call tool_help(name) to get its usage before you use it.
7) USE SKILLS: you have a library of attack techniques. Call list_skills() to see categories, then load_skill(name)
   to inject the matching technique before testing that vuln class (e.g. SQLi -> sql_injection, XSS -> xss, SSRF -> ssrf).
   A loaded skill tells you HOW to do it step-by-step (payloads, judge rules). Always load the relevant skill before GUESSING.
"""

# ---------------------------------------------------------------------------
# 记忆层
# ---------------------------------------------------------------------------

class _Memory:
    def __init__(self, db_path: str):
        self.db = db_path
        self._init()

    def _init(self):
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS agent_memory (
                key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)""")
            conn.commit()
        finally:
            conn.close()

    def get(self, key: str) -> Optional[str]:
        conn = sqlite3.connect(self.db)
        try:
            r = conn.execute("SELECT value FROM agent_memory WHERE key=?", (key,)).fetchone()
            return r[0] if r else None
        finally:
            conn.close()

    def set(self, key: str, value: str):
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("INSERT OR REPLACE INTO agent_memory(key,value,updated_at) VALUES(?,?,?)",
                         (key, value, time.strftime("%Y-%m-%dT%H:%M:%S")))
            conn.commit()
        finally:
            conn.close()

    def context_block(self) -> str:
        conn = sqlite3.connect(self.db)
        try:
            rows = conn.execute("SELECT key,value FROM agent_memory").fetchall()
        finally:
            conn.close()
        if not rows:
            return ""
        return "=== MEMORY ===\n" + "\n".join(f"{k}: {v}" for k, v in rows) + "\n=== END MEMORY ==="

# ---------------------------------------------------------------------------
# 工具 schema 构建（OpenAI function calling 格式）
# ---------------------------------------------------------------------------

def build_tools_schema(tool_names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """从 TOOL_REGISTRY 构建 OpenAI tools 参数。"""
    schema = []
    for name, t in TOOL_REGISTRY.items():
        if tool_names and name not in tool_names:
            continue
        params = t.schema or {"type": "object", "properties": {}}
        schema.append({
            "type": "function",
            "function": {
                "name": name,
                "description": t.description,
                "parameters": params,
            },
        })
    return schema

# ---------------------------------------------------------------------------
# 执行器
# ---------------------------------------------------------------------------

def _prepare_args(tool_def, args: Dict[str, Any], container: Optional[str], workdir: str = "") -> Dict[str, Any]:
    """按 handler 签名过滤参数：LLM 可能多传 handler 不接受的键（如 user/container），丢弃之；
    若 handler 接受 container/workdir 则注入。有 **kwargs 则原样保留。"""
    if tool_def is None:
        return args
    try:
        sig = inspect.signature(tool_def.handler)
        params = sig.parameters
    except (TypeError, ValueError):
        return args
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        if container and "container" not in args:
            args["container"] = container
        if workdir and "workdir" not in args:
            args["workdir"] = workdir
        return args
    filtered = {k: v for k, v in args.items() if k in params}
    if container and "container" in params and "container" not in filtered:
        filtered["container"] = container
    if workdir and "workdir" in params and "workdir" not in filtered:
        filtered["workdir"] = workdir
    return filtered


# ---- 上下文工程（工具输出截断 + 历史 compaction，治 prompt 膨胀变慢）----
TOOL_OUTPUT_MAX_CHARS = int(os.environ.get("HINSE_TOOL_OUT_CHARS", "8000"))  # ≈2-3K tokens
CONTEXT_BUDGET_CHARS = int(os.environ.get("HINSE_CONTEXT_BUDGET", "80000"))  # 全局 context 闸（chars，超限即压）
_COMPACT_PLACEHOLDER = "[earlier tool output omitted — context budget]"
_TOOLCALL_ARGS_OMITTED = '{"omitted": "context budget"}'  # 合法 JSON，保持 tool_calls 结构可被 API 接受
_ASSISTANT_TEXT_OMITTED = "[earlier assistant reasoning omitted — context budget]"

def _strip_payloads(content: str) -> str:
    """剥离 SQLi 载荷模式（DeepSeek-V4-Flash 内容过滤对 SQLi 载荷硬 500），保留 JSON 结构与元数据。"""
    try:
        from agents.tools import _PAYLOAD_RE
        if _PAYLOAD_RE.search(content):
            return _PAYLOAD_RE.sub("[REDACTED_PAYLOAD]", content)
    except Exception:
        pass
    return content


def _truncate_tool_output(content: str) -> str:
    """工具输出超上限则截断 + 标注（字符版）。同时剥离 SQLi 载荷模式（见 _strip_payloads）。"""
    content = _strip_payloads(content)
    limit = int(cfg_env("HINSE_TOOL_OUT_CHARS", "8000"))
    if len(content) <= limit:
        return content
    total = len(content)
    return content[:limit] + f"\n...[TRUNCATED: {total} chars total, kept first {limit}]"


def _arg_error(tool_name: str, tool_def, exc: TypeError, args: dict = None) -> str:
    """工具参数 TypeError → 给模型可操作的错误（列必填参数+实际给了什么+示例），
    治「missing code/path 反复重试烧轮次」（forensics-5 曾 22 errors/126 tools）。"""
    import inspect
    try:
        sig = inspect.signature(tool_def.handler)
        required = [p.name for p in sig.parameters.values()
                    if p.default is inspect.Parameter.empty
                    and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)]
        # 更精确：从异常文本提取缺失参数名
        m = re.search(r"missing \d+ required positional argument: '(\w+)'", str(exc))
        miss = [m.group(1)] if m else required
        ex_args = ", ".join(f'{n}="..."' for n in required[:4]) or f'{miss[0]}="..."'
        got = sorted(k for k in (args or {}) if k not in ("container", "workdir"))
        got_s = f" You provided: {', '.join(got[:8])}." if got else " You provided no arguments."
        # 非"缺参数"型 TypeError（如参数类型不对：list/dict 传给字符串参数）要带原始异常，
        # 否则会误报成"missing required X"（qwen 发 ["line1","line2"] 实测踩过）。
        detail = "" if m else f" Cause: {type(exc).__name__}: {str(exc)[:120]}."
        return (f"invalid arguments for {tool_name}: missing required '{', '.join(miss)}'."
                f"{got_s}{detail} Required: {', '.join(required[:6]) or 'check schema'}. "
                f"Call again with e.g. {{{ex_args}}}")
    except Exception:
        return f"invalid arguments for {tool_name}: {exc}"


def _required_params(tool_def) -> list:
    """工具 handler 的必填参数名（无默认值的位置/关键字参数）。"""
    import inspect
    try:
        sig = inspect.signature(tool_def.handler)
        return [p.name for p in sig.parameters.values()
                if p.default is inspect.Parameter.empty
                and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)]
    except Exception:
        return []


def _validate_tool_calls(tool_calls) -> list:
    """本地预校验 tool_calls（JSON 可解析 + 必填参数齐）；返回问题清单（空=全有效）。
    执行前拦截"空参数/坏 JSON"，供 _try_repair_calls 一轮自愈，不再烧整轮走错误回传。"""
    problems = []
    for i, tc in enumerate(tool_calls or []):
        fn = (tc or {}).get("function") or {}
        name = fn.get("name") or "?"
        raw = fn.get("arguments")
        if isinstance(raw, dict):
            args = raw
        else:
            try:
                args = json.loads(raw or "{}")
            except Exception:
                problems.append(f"#{i + 1} {name}: arguments 不是合法 JSON（原样: {str(raw)[:60]}）")
                continue
        if not isinstance(args, dict):
            problems.append(f"#{i + 1} {name}: arguments 必须是 JSON 对象")
            continue
        tdef = get_tool(str(name))
        if tdef is None:
            problems.append(f"#{i + 1} {name}: unknown tool（不在你的工具列表里）")
            continue
        missing = [r for r in _required_params(tdef)
                   if r not in args and r not in ("container", "workdir", "task_id")]
        if missing:
            problems.append(f"#{i + 1} {name}: 缺必填参数 {', '.join(missing[:5])}（你给的是: "
                            f"{', '.join(list(args)[:8]) or '无'}）")
    return problems


TOOL_OUTPUT_DIR = os.path.join(DATA_DIR, "tool_outputs")


def _save_full_tool_output(task_id: str, output_id: str, full: str) -> Optional[int]:
    """大工具输出全文落盘（原始数据保留；检索侧 query_tool_output 再剥离载荷）。
    单行 JSON 缩进格式化——否则整个结果是 1 行，分页/关键词按行检索失效。
    返回落盘行数（失败 None）。"""
    if not task_id or not output_id:
        return None
    try:
        if "\n" not in full:
            s = full.lstrip()
            if s[:1] in ("{", "["):
                full = json.dumps(json.loads(full), ensure_ascii=False, indent=1)
        tid = re.sub(r"[^A-Za-z0-9_-]", "_", str(task_id))[:80]
        oid = re.sub(r"[^A-Za-z0-9_-]", "_", str(output_id))[:100]
        d = os.path.join(TOOL_OUTPUT_DIR, tid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, oid + ".txt"), "w", encoding="utf-8", errors="replace") as f:
            f.write(full)
        return len(full.splitlines())
    except Exception:
        return None


def _tool_result_content(result: Any, task_id: str, output_id: str) -> str:
    """工具结果的上下文内容：小输出原样；大输出全文落盘 + 留头部 + 检索指针
    （替代旧"硬截断丢弃"——agent 可用 query_tool_output 按页/关键词取回全文）。"""
    full = json.dumps(result, ensure_ascii=False, default=str)
    limit = int(cfg_env("HINSE_TOOL_OUT_CHARS", "8000"))
    if len(full) <= limit:
        return _truncate_tool_output(full)
    n_lines = _save_full_tool_output(task_id, output_id, full)
    if n_lines:
        safe_head = _strip_payloads(full)[:limit]
        return (safe_head
                + f"\n...[TRUNCATED] FULL OUTPUT SAVED ({len(full)} chars, {n_lines} lines) — "
                + f"use query_tool_output(output_id=\"{output_id}\", page=1, keyword=\"<search term>\") to retrieve the rest")
    return _truncate_tool_output(full)


def cleanup_task_tool_outputs(task_id: str) -> int:
    """任务结束后清理其大输出落盘（只供任务内检索）。返回清理文件数。"""
    if not task_id:
        return 0
    d = os.path.join(TOOL_OUTPUT_DIR, re.sub(r"[^A-Za-z0-9_-]", "_", str(task_id))[:80])
    if not os.path.isdir(d):
        return 0
    n = sum(len(files) for _, _, files in os.walk(d))
    try:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    except Exception:
        pass
    return n


def _case_redact(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value or "")
    return sanitize_text(text).content


def _case_tool_call_id(tc: Dict[str, Any]) -> str:
    return str(tc.get("id") or f"call_{len(tc.get('_recent', []))}")


def _tool_args(tc: Dict[str, Any]) -> Dict[str, Any]:
    fn = tc.get("function", {})
    try:
        return json.loads(fn.get("arguments") or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}


def build_inhouse_case_snapshot(
    task_id: str,
    target: str,
    target_id: str,
    model: str,
    runtime_id: str,
    findings: Optional[List[Dict[str, Any]]] = None,
    coverage: Optional[List[Dict[str, Any]]] = None,
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    llm_turns: int = 0,
    modules: Optional[List[str]] = None,
    phases: Optional[List[Dict[str, Any]]] = None,
    evidence_refs: Optional[List[str]] = None,
    summary: str = "",
) -> CaseSnapshot:
    findings = findings or []
    coverage = coverage or []
    tool_calls = tool_calls or []
    target_id = target_id or resolve_target_id(target, "")
    snapshot_findings = [
        FindingSnapshot(
            id=f.get("id", ""),
            status=str(f.get("status", "found")),
            severity=str(f.get("severity", "medium")),
            dedup_key=str(f.get("dedup_key") or f"{f.get('title','')}@{f.get('asset','')}"),
        )
        for f in findings
    ]
    snapshot_coverage = [
        CoverageSnapshot(
            id=int(c.get("id", 0)),
            surface=str(c.get("surface", "")),
            risk_area=str(c.get("risk_area", "")),
            outcome=str(c.get("outcome", "no_issue_found")),
            evidence_hash=hash_text(_case_redact(c.get("evidence", ""))),
        )
        for c in coverage
    ]
    snapshot_tools = [
        ToolCallSnapshot(
            name=str(tc.get("name", "")),
            status=str(tc.get("status", "ok")),
            started_at=str(tc.get("started_at") or time.strftime("%Y-%m-%dT%H:%M:%S")),
            ended_at=str(tc.get("ended_at") or time.strftime("%Y-%m-%dT%H:%M:%S")),
            args_redacted=_case_redact(tc.get("args", {})),
            result_redacted=_case_redact(tc.get("result", {})),
        )
        for tc in tool_calls
    ]
    captured_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    raw = {
        "schema_version": 1,
        "source_type": "inhouse",
        "source_id": task_id,
        "source_flow": None,
        "agent": "RedBee",
        "model": model,
        "runtime_id": runtime_id,
        "task": f"RedBee task {task_id}",
        "target": target,
        "target_id": target_id,
        "summary": summary or "",
        "modules": modules or [],
        "phases": phases or [],
        "findings": [f.model_dump() for f in snapshot_findings],
        "coverage": [c.model_dump() for c in snapshot_coverage],
        "trajectory": TrajectorySnapshot(
            tool_calls=snapshot_tools,
            llm_turns={"count": int(llm_turns)},
            raw_evidence_ref=evidence_refs or [],
        ).model_dump(),
        "provenance": ProvenanceSnapshot(
            captured_at=captured_at,
            adapter_version="inhouse-case-capture-v1",
            raw_size_bytes=len(json.dumps({"findings": findings, "coverage": coverage, "tool_calls": tool_calls}, default=str)),
            sanitized=True,
        ).model_dump(),
    }
    return CaseSnapshot.model_validate(raw)


def store_inhouse_case(snapshot: CaseSnapshot,
                       evidence_by_id: Optional[Dict[str, str]] = None) -> str:
    case_id = submit_case(snapshot)
    evidence_by_id = evidence_by_id or {}
    for evidence_id in snapshot.trajectory.raw_evidence_ref:
        content = evidence_by_id.get(evidence_id)
        if content:
            add_case_evidence(case_id, evidence_id, content, kind="finding")
    return case_id


# ---------------------------------------------------------------------------
# 任务级沙箱容器注册表（stop 任务时物理杀容器用）
# ---------------------------------------------------------------------------
ACTIVE_CONTAINERS: Dict[str, str] = {}  # container name -> task_id


def register_container(name: str, task_id: str = "") -> None:
    if name:
        ACTIVE_CONTAINERS[name] = task_id or ""


def unregister_container(name: str) -> None:
    if name:
        ACTIVE_CONTAINERS.pop(name, None)


async def kill_containers_for_task(task_id: str) -> int:
    """docker rm -f 该 task 名下全部沙箱（物理终止容器内所有攻击命令 + 宿主机 docker exec 客户端）。"""
    if not task_id:
        return 0
    names = [n for n, t in list(ACTIVE_CONTAINERS.items()) if t == task_id]
    for n in names:
        try:
            proc = await asyncio.create_subprocess_shell(f"docker rm -f {n}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.wait_for(proc.communicate(), timeout=10)
            print(f"[kill-container] task={task_id} {n} killed", flush=True)
        except Exception as e:
            print(f"[kill-container] task={task_id} {n} error: {type(e).__name__}: {e}", flush=True)
        ACTIVE_CONTAINERS.pop(n, None)
    return len(names)


async def kill_orphan_containers(prefix: str = "inhouse-sess-") -> int:
    """杀掉所有匹配前缀的沙箱容器（网关重启后的孤儿：内存态已丢，任何存活的 inhouse-* 都属死进程）。
    传逗号分隔多前缀（docker name filter 多值 = OR）：inhouse-sess-(单agent) + inhouse-task-(任务级共享)。"""
    filters = " ".join(f"--filter name={p.strip()}" for p in prefix.split(",") if p.strip())
    try:
        proc = await asyncio.create_subprocess_shell(
            f"docker ps -q {filters}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        ids = [x for x in out.decode().split() if x]
    except Exception as e:
        print(f"[kill-orphan] list error: {type(e).__name__}: {e}", flush=True)
        return 0
    for cid in ids:
        try:
            p = await asyncio.create_subprocess_shell(f"docker rm -f {cid}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.wait_for(p.communicate(), timeout=10)
            print(f"[kill-orphan] {cid} killed", flush=True)
        except Exception as e:
            print(f"[kill-orphan] {cid} error: {type(e).__name__}: {e}", flush=True)
    return len(ids)


class InhouseAgent:
    """自研渗透智能体 — 基于 TOOL_REGISTRY 的 ReAct 循环 + function calling。"""

    def __init__(self, runtime: Optional[ResolvedRuntime] = None, memory: Optional[_Memory] = None):
        self.runtime = coerce_resolved_runtime(runtime) if runtime is not None else None
        self.state = _State()
        self.memory = memory or _Memory(DB_PATH)
        self.recent_calls: List[str] = []
        self.messages: List[Dict[str, Any]] = []
        self.container: Optional[str] = None
        self.workdir: str = ""          # 容器内工作目录（共享容器下按 agent 隔离，/work/<module>）
        self._owns_container = True     # False = 任务级共享容器，_cleanup 不删（由编排层统一回收）
        self._unlocked_tools: set = set()  # 运行时 load_skill 解锁的专业工具（skill-gated tools）
        self.tools_schema = self._render_tools_schema()
        self._has_recorded = False  # 是否已 submit_finding/record_coverage（收口进度自查用）
        self._text_only_streak = 0  # 连续无工具调用轮次（治"done 词不匹配→空转烧轮次"）
        self._bad_json_streak = 0  # 连续出现坏 JSON tool-call 的轮次（触发纠错提示）
        self._arg_error_streak = 0  # 连续参数缺失 TypeError 轮次（≥2 注入纠错，治 missing code 连击）
        self._repair_budget = int(cfg_env("HINSE_ARG_REPAIR_BUDGET", "8"))  # 空参数一轮自愈的次数预算
        self._uid = uuid.uuid4().hex[:8]  # agent 实例标识：大输出落盘 output_id 前缀（同任务多子 agent 并行不撞名）
        self._exit_reason = ""  # 主循环退出原因：text_done(自然收口) / budget(耗尽)
        self.final_summary = ""  # 预算耗尽时的强制收口总结（喂 case snapshot/报告）
        self._tool_started: Dict[str, str] = {}
        self._tool_ended: Dict[str, str] = {}
        self._ctf_flag_watch = False  # CTF 模式（编排层 stop_check 在场时置 True）：工具流 flag 识别
        self._flag_nudged: set = set()  # 已提醒过的 flag 值（去重防刷屏）
        # 失败自恢复环（2026-10-28，治 m3-s2 型"文件缺失→反复 ls/cat 一小时"空转）：
        self._repeat_streak = 0        # 连续重复调用轮次（warn 递增/无 warn 清零；每 3 次注入重定向）
        self._enoent_seen: Dict[str, int] = {}  # 路径 → ENOENT 出现次数
        self._enoent_nudged: set = set()        # 已注入过恢复提示的路径
        self._stuck_nudges = 0         # 重定向注入总数（封顶 4 防刷屏）
        self._initial_brief = ""       # 首条 user 消息快照（重注入用——上下文压缩后原始配方会丢）
        self.pending_notes: List[str] = []  # 飞行中指令（in-run steer），每轮 LLM 调用前排空
        self._task_text: str = ""  # 任务原文（CTF 模式判断用）

    def inject_note(self, text: str) -> None:
        """外部注入一条用户补充指令（任务执行中）。从下一个 LLM 轮次生效。"""
        if text and text.strip():
            self.pending_notes.append(text.strip())

    def _drain_notes(self) -> None:
        while self.pending_notes:
            note = self.pending_notes.pop(0)
            print(f"[steer] 飞行中指令注入 agent 上下文: {note[:100]}", flush=True)
            _tlog(getattr(self, "last_task_id", ""), "steer",
                  f"注入指令: {note[:160]}", getattr(self, "_current_module", ""))
            self.messages.append({"role": "user", "content":
                f"【用户补充指令】{note}\n"
                "(User instruction received DURING execution. Adjust your subsequent actions accordingly. "
                "Keep the overall task goal; if the instruction conflicts with your assigned module boundary, "
                "follow your module and ignore the conflicting part.)"})

    def _context_size(self) -> int:
        """当前 messages 总字符数（粗估 context 大小；中文≈1 token/char，英文≈0.3）。
        必须与 _chat 实际发送口径一致：content + tool_calls。
        旧版只算 content——模型 tool_calls 里的 curl/payload 参数对闸门不可见，
        闸以为 ≤预算 实际已 1M（R7 csrf 模块实测 1.07M chars，预算 80K 形同虚设）。"""
        return sum(len(str(m.get("content") or "")) + sum(len(str(tc)) for tc in (m.get("tool_calls") or []))
                   for m in self.messages)

    def _compact_messages(self) -> None:
        """历史 compaction（全局闸，规则版零 LLM 成本）：
        保留 system(0)+首条 user(1) 不动，从最老消息起把
        ① tool output(>200 chars) ② assistant 已执行完的 tool_calls arguments(>200 chars)
        ③ assistant 长文本(>500 chars) 替换成占位符，
        压到 总 ctx <= CONTEXT_BUDGET_CHARS 或无可压。
        按"总大小"触发（治条数多也治单条大），比旧版"按条数"更贴合 token 成本。
        tool_calls 只换 arguments 保 id（与后续 tool 结果的配对不断裂）。
        旧版只压 tool 输出：assistant tool_calls 无人管形成压不下的地板（R7 实证）。"""
        n = len(self.messages)
        if n <= 2:
            return
        size = self._context_size()
        budget = int(cfg_env("HINSE_CONTEXT_BUDGET", "80000"))
        if size <= budget:
            return
        for i in range(2, n):
            if size <= budget:
                break
            m = self.messages[i]
            content = str(m.get("content") or "")
            if m.get("role") == "tool" and len(content) > 200:
                size += len(_COMPACT_PLACEHOLDER) - len(content)
                m["content"] = _COMPACT_PLACEHOLDER
            elif m.get("role") == "assistant":
                for tc in (m.get("tool_calls") or []):
                    fn = tc.get("function") or {}
                    args = str(fn.get("arguments") or "")
                    if len(args) > 200:
                        size += len(_TOOLCALL_ARGS_OMITTED) - len(args)
                        fn["arguments"] = _TOOLCALL_ARGS_OMITTED
                if len(content) > 500:
                    size += len(_ASSISTANT_TEXT_OMITTED) - len(content)
                    m["content"] = _ASSISTANT_TEXT_OMITTED

    # ---- 工具门控（skill-gated tools）----

    def _current_tool_names(self) -> List[str]:
        """当前 agent 可见工具 = 核心集 ∪ 已解锁（按 registry 过滤）。"""
        names = (set(TOOL_REGISTRY) - GATED_TOOLS) | self._unlocked_tools
        return sorted(names & set(TOOL_REGISTRY))

    def _render_tools_schema(self) -> List[Dict[str, Any]]:
        return build_tools_schema(self._current_tool_names())

    def _unlock(self, skill_name: str) -> List[str]:
        """按 skill 名解锁工具，返回**新**解锁的（已解锁的不重复报）。"""
        key = resolve_skill_name(skill_name)
        if key is None:
            key = (skill_name or "").strip()
        tools = TOOL_UNLOCK_MAP.get(key) or set()
        new = tools - self._unlocked_tools
        if new:
            self._unlocked_tools |= new
            self.tools_schema = self._render_tools_schema()
            print(f"[tools] 解锁 skill={key} -> {sorted(new)}（{self._uid}）", flush=True)
        return sorted(new)

    def _auto_unlock(self, module: Optional[str]) -> None:
        """角色自动解锁：module 的聚焦 skill 命中解锁表则开箱即用（如 sqli→sqlmap 族）；
        'generic'（pre-recon/recon 任务级 agent）→ 侦察工具族。"""
        if not module:
            return
        for key in _MODULE_AUTO_UNLOCK.get(module, ()):
            self._unlock(key)
        self._unlock(module)  # resolve_skill_name 处理别名（sqli→sql-injection）；无映射则空操作

    async def _chat(self, messages: List[Dict[str, Any]], max_tokens: int = 4096,
                    temperature: float = 0.3, runtime: Optional[ResolvedRuntime] = None) -> Dict[str, Any]:
        """通过统一运行时请求模型，失败不切换私有默认值。"""
        selected = coerce_resolved_runtime(runtime or self.runtime)
        # LLM 观测：每次调用打 n_msg(消息数) / ctx(上下文字符数,近似) / el(耗时秒)。治"context 膨胀看不到"。
        _n_msg = len(messages)
        _ctx = sum(len(m.get("content") or "") + sum(len(str(tc)) for tc in (m.get("tool_calls") or []))
                   for m in messages)
        _t0 = time.monotonic()
        payload = {
            "model": selected.runtime.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "tools": self.tools_schema,
            "tool_choice": "auto",
            "stream": False,
        }
        result = await RuntimeClient.chat(selected, payload)
        _el = time.monotonic() - _t0
        if not result.ok or result.error:
            print(f"[llm] n_msg={_n_msg} ctx={_ctx} el={_el:.1f}s FAIL: {(result.error.redacted_message if result.error else 'model runtime failed')[:80]}", flush=True)
            _tlog(getattr(self, "last_task_id", ""), "llm",
                  f"FAIL n_msg={_n_msg} ctx={_ctx} el={_el:.1f}s {(result.error.redacted_message if result.error else 'model runtime failed')[:160]}",
                  getattr(self, "_current_module", ""))
            raise RuntimeError(result.error.redacted_message if result.error else "model runtime failed")
        print(f"[llm] n_msg={_n_msg} ctx={_ctx} el={_el:.1f}s tools={len(result.tool_calls or [])}", flush=True)
        _tlog(getattr(self, "last_task_id", ""), "llm",
              f"n_msg={_n_msg} ctx={_ctx} el={_el:.1f}s tools={len(result.tool_calls or [])}",
              getattr(self, "_current_module", ""))
        return {"role": "assistant", "content": result.content, "tool_calls": result.tool_calls}

    async def _chat_stream_once(self, payload: Dict[str, Any], transient: tuple,
                                runtime: Optional[ResolvedRuntime] = None) -> Dict[str, Any]:
        """兼容旧调用；实际执行仍走 RuntimeClient.chat。"""
        selected = coerce_resolved_runtime(runtime or self.runtime)
        result = await RuntimeClient.chat(selected, payload)
        if not result.ok or result.error:
            raise RuntimeError(result.error.redacted_message if result.error else "model runtime failed")
        return {"role": "assistant", "content": result.content, "tool_calls": result.tool_calls}

    # ---- 主循环 ----

    async def run(self, task: str, target: str, model: str = "",
                  runtime: Optional[ModelRuntime] = None,
                  task_id: str = "", module: Optional[str] = None,
                  target_path: str = "") -> Dict[str, Any]:
        selected = runtime or self.runtime
        if selected is None:
            return self._fail("runtime required")
        self.last_task_id = task_id
        module = module or self._infer_module(task)
        self._build_initial_messages(target, module, task)
        self.container = await self._docker_run(target_path)
        register_container(self.container, task_id)

        deadline = time.monotonic() + float(getattr(self, "TASK_BUDGET", None) or cfg_env("HINSE_TASK_BUDGET", "1800"))
        while self.state.tool_calls < _max_turns(self) and time.monotonic() < deadline:
            self._compact_messages()
            self._inject_budget_notice()
            self._drain_notes()
            try:
                msg = await self._chat(self.messages, runtime=selected)
            except Exception as e:
                await self._cleanup()
                return self._fail(str(e))
            self.state.turn += 1
            tool_calls = msg.get("tool_calls")
            if tool_calls:
                tool_calls = await self._try_repair_calls(tool_calls, selected)
                self._text_only_streak = 0
                self.messages.append({
                    "role": "assistant",
                    "content": msg.get("content") or "",
                    "tool_calls": [_openai_tool_call_obj(tc) for tc in tool_calls],
                })
                await self._exec_tool_calls(tool_calls, task_id, target)
            else:
                self._text_only_streak += 1
                self.messages.append({"role": "assistant", "content": msg.get("content") or ""})
                # 无工具调用 = 最终答复(ReAct 约定)。连续 2 轮纯文本即收口,
                # 治 done 措辞不匹配时无限重查同一 context 空烧轮次。
                if self._done_in_content(msg.get("content") or "") or self._text_only_streak >= 2:
                    self._exit_reason = "text_done"
                    break

        if self._exit_reason != "text_done":
            # 预算/轮次耗尽（非自然收口）→ 强制一次收口总结，治"静默停、无结论"
            self.final_summary = await self._final_wrapup(selected, task_id, target)
        await self._cleanup()
        return self._finalize(task_id, target, selected)

    async def run_stream(self, task: str, target: str, model: str = "",
                         runtime: Optional[ModelRuntime] = None,
                         task_id: str = "", module: Optional[str] = None,
                         target_path: str = "") -> AsyncIterator[Dict[str, Any]]:
        selected = runtime or self.runtime
        if selected is None:
            yield {"type": "error", "runtime_id": "", "error": "runtime required"}
            return
        self.last_task_id = task_id
        module = module or self._infer_module(task)
        self._build_initial_messages(target, module, task)
        self.container = await self._docker_run(target_path)
        register_container(self.container, task_id)
        yield {"type": "start", "runtime_id": selected.runtime_id,
               "content": f"Analyzing {module} on {target}... (container={self.container})"}

        deadline = time.monotonic() + float(getattr(self, "TASK_BUDGET", None) or cfg_env("HINSE_TASK_BUDGET", "1800"))
        while self.state.tool_calls < _max_turns(self) and time.monotonic() < deadline:
            self._compact_messages()
            self._inject_budget_notice()
            self._drain_notes()
            try:
                msg = await self._chat(self.messages, runtime=selected)
            except Exception as e:
                await self._cleanup()
                yield {"type": "error", "runtime_id": selected.runtime_id, "error": str(e)}
                return
            self.state.turn += 1
            tool_calls = msg.get("tool_calls")
            if tool_calls:
                tool_calls = await self._try_repair_calls(tool_calls, selected)
                self._text_only_streak = 0
                self.messages.append({
                    "role": "assistant",
                    "content": msg.get("content") or "",
                    "tool_calls": [_openai_tool_call_obj(tc) for tc in tool_calls],
                })
                async for event in self._exec_tool_calls_stream(tool_calls, task_id, target):
                    yield event
            else:
                self._text_only_streak += 1
                self.messages.append({"role": "assistant", "content": msg.get("content") or ""})
                yield {"type": "text", "runtime_id": selected.runtime_id,
                       "content": msg.get("content") or ""}
                if self._done_in_content(msg.get("content") or "") or self._text_only_streak >= 2:
                    self._exit_reason = "text_done"
                    break

        if self._exit_reason != "text_done":
            # 预算/轮次耗尽（非自然收口）→ 强制一次收口总结，治"静默停、无结论"
            self.final_summary = await self._final_wrapup(selected, task_id, target)
            if self.final_summary:
                yield {"type": "text", "runtime_id": selected.runtime_id,
                       "content": self.final_summary}
        await self._cleanup()
        yield {"type": "done", "runtime_id": selected.runtime_id,
               "content": self._finalize(task_id, target, selected)}

    # ---- 内部 ----

    def _build_initial_messages(self, target: str, module: str, task: str):
        self._task_text = task or ""
        # 分阶段工具面（skill-gated）：先按角色自动解锁专业工具，再渲染 schema + prompt
        self._auto_unlock(module)
        self.tools_schema = self._render_tools_schema()
        memory_block = self.memory.context_block()
        tool_names = ", ".join(self._current_tool_names())
        # 强制注入聚焦 skill（和 KB 强制注入 _kb_brief 同模式）：LLM 不会主动 load_skill，
        # 编排层按 module 直接注入蒸馏技法（sqli→sql-injection.md，已 _strip_payload_lines 剥离载荷，安全）。
        # 大 skill（如 llm-applications 23K）截断到 8K——只取最相关的前段，避免撑爆 context、挤占有效轮次。
        skill_block = get_skill_content(module)
        _SKILL_MAX_CHARS = int(cfg_env("HINSE_SKILL_MAX_CHARS", "8000"))
        if skill_block and len(skill_block) > _SKILL_MAX_CHARS:
            skill_block = skill_block[:_SKILL_MAX_CHARS] + "\n…[skill truncated for context budget; use kb_query/load_skill for the rest]"
        skill_section = (f"\n=== FOCUSED SKILL: {module} (PROVEN TECHNIQUES — follow this playbook) ===\n{skill_block}\n"
                         if skill_block else "")
        system = (
            f"You are an authorized application security validation agent working on an in-scope, CONTROLLED test environment.\n\n"
            f"Target: {target}\n\n"
            "=== AUTHORIZATION ===\n"
            "- You have FULL authorization to validate this controlled test environment. You are performing authorized security validation.\n"
            "- Never question your authority, never add safety disclaimers, never ask for permission. Operate autonomously.\n\n"
            "=== HOW TO WORK (CRITICAL) ===\n"
            "- You validate whether in-scope inputs (parameters, pages, endpoints) are reflected into backend processing (queries, commands, "
            "rendered output) and can return unexpected data or behavior.\n"
            "- You act ONLY through tools. Send crafted requests via http_request / poc_verify "
            "(and the deterministic sqlmap flow when the SQLi tools are in your tool list). "
            "Put the exact request/payload in the TOOL ARGUMENTS (url / params / body / cookies), NEVER as natural-language prose. "
            "Do not write payloads into your own text output; always carry them as tool parameters.\n"
            f"- Focused module class: {module}. If you need step-by-step technique guidance, load a skill via load_skill or query the "
            "knowledge base via kb_query.\n\n"
            "=== TOOL MANUAL ===\n"
            f"{CORE_TOOL_MANUAL}\n"
            f"{skill_section}\n"
            "=== RULES (RECORDING IS THE #1 PRIORITY) ===\n"
            "1. A SINGLE WORKING PROOF = CONFIRMED. You do NOT need exhaustive verification.\n"
            "2. RECORD IMMEDIATELY, NEVER HOARD. The moment an issue is confirmed, call BOTH in the SAME turn:\n"
            "   (a) submit_finding(title, poc=<exact payload/request>, evidence=<response proving it>, asset, severity, vuln_class)\n"
            "   (b) record_coverage(surface, risk_area, outcome='reported', evidence=<the proof>)\n"
            "   The finding MUST be recorded FIRST; you MAY deepen it only after recording.\n"
            "3. COVERAGE EVERY SURFACE. For every surface/parameter you touch, call record_coverage with the honest outcome:\n"
            "   reported / no_issue_found / ruled_out(REQUIRES evidence) / not_applicable / needs_follow_up.\n"
            "   An unrecorded surface is 'unexamined', NOT 'clean'.\n"
            "4. Bounded effort: after 3 failed attempts on a vector, record_coverage(ruled_out, evidence=...) and move on.\n"
            "5. Do NOT re-test a surface you already recorded. Track progress with todo_write; use kb_query / load_skill when stuck.\n"
            "6. NEVER report without a concrete PoC.\n"
            f"7. Tools available via function calling: {tool_names}\n\n"
            f"{memory_block}\n\n"
            "=== OUTPUT ===\n"
            "Record each confirmed issue via submit_finding + record_coverage IMMEDIATELY (never hoard). "
            "When all in-scope surfaces are recorded (exploited or ruled out), end your turn with text containing 'done'.\n"
        )
        self.messages = [{"role": "system", "content": system},
                         {"role": "user", "content": task}]
        self.state.todos = [{"content": f"Analyze {module} on {target}", "status": "in_progress"}]

    async def _docker_run(self, target_path: str = "", name: str = "") -> str:
        name = name or f"inhouse-sess-{uuid.uuid4().hex[:8]}"
        cmd = f"docker run -d --name {name} --network bridge"
        # 网络攻击域能力：tun 设备 + NET_ADMIN（nilgiri M1.s4 起需在沙箱内建 OpenVPN 隧道
        # 打进隔离网段；无此能力的任务不受影响——只是容器多了 tun 设备）
        if str(cfg_env("HINSE_SANDBOX_NET_CAP", "1")) not in ("0", "false"):
            cmd += " --cap-add NET_ADMIN --device /dev/net/tun"
        if target_path:
            cmd += f" -v {target_path}:/target"
        cmd += f" {_kali_image()} tail -f /dev/null"
        proc = await asyncio.create_subprocess_shell(cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=15)
        if proc.returncode != 0:
            raise RuntimeError(f"docker run failed: {err.decode()}")
        return name

    async def _cleanup(self):
        if self.container:
            unregister_container(self.container)
            # 共享容器（_owns_container=False）由编排层任务级统一回收，这里不删
            if self._owns_container:
                proc = await asyncio.create_subprocess_shell(
                    f"docker rm -f {self.container}",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                await asyncio.wait_for(proc.communicate(), timeout=15)
            self.container = None

    def _infer_module(self, task: str) -> str:
        t = task.lower()
        for m in ("sqli", "sql injection"):
            if m in t: return "sqli"
        for m in ("xss", "cross-site"):
            if m in t: return "xss"
        for m in ("auth", "login", "password"):
            if m in t: return "auth"
        for m in ("upload", "file"):
            if m in t: return "upload"
        return "generic"

    def _done_in_content(self, content: str) -> bool:
        c = (content or "").strip().lower()
        if not c:
            return False
        return ('"done"' in c or "`done`" in c or c.startswith("done"))

    # ---- tool 执行 ----

    async def _try_repair_calls(self, tool_calls: List[Dict[str, Any]], runtime) -> List[Dict[str, Any]]:
        """坏参数 tool-call 一轮自愈（2026-10-21）：主 LLM 返回后本地预校验，无效则立即
        一次"仅修复"调用（不进主历史、不烧轮次/turn 计数），修复失败回落原批次走既有错误路径。

        实测动机：locktalk DeepSeek 时代 57 次 "missing required X"（26% 轮次浪费）、
        failproof 75/220 轮（34%）——错误回传+下轮重试的老路径每错一次烧一整轮。"""
        problems = _validate_tool_calls(tool_calls)
        if not problems or self._repair_budget <= 0:
            return tool_calls
        self._repair_budget -= 1
        repair_msgs = list(self.messages) + [
            {"role": "assistant", "content": "",
             "tool_calls": [_openai_tool_call_obj(tc) for tc in tool_calls]},
            {"role": "user", "content": (
                "[ARG REPAIR] 你刚才输出的 tool_calls 参数无效，没有被执行：\n"
                + "\n".join(f"- {p}" for p in problems)
                + "\n请重新输出修正后的 tool_calls（保持 function calling 原格式、arguments 为完整 JSON"
                  " 对象、含全部必填参数）。只输出修正后的 tool_calls，不要解释、不要换工具。")},
        ]
        try:
            fixed = await self._chat(repair_msgs, runtime=runtime)
        except Exception:
            return tool_calls
        new_calls = fixed.get("tool_calls")
        if not new_calls or _validate_tool_calls(new_calls):
            return tool_calls  # 修复失败 → 原批次走既有错误路径（永不更差）
        _tlog(self.last_task_id, "tool",
              f"[arg-repair] 一轮自愈 {len(problems)} 个坏参数调用",
              getattr(self, "_current_module", ""))
        return new_calls

    async def _exec_tool_calls(self, tool_calls: List[Dict[str, Any]],
                                   task_id: str, target: str,
                                   progress_cb=None):
        bad_json = 0
        for tc in tool_calls:
            fn = tc.get("function", {})
            tool_name = fn.get("name")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = None
            tool_def = get_tool(tool_name)
            call_id = str(tc.get("id") or f"call_{self.state.tool_calls}")
            if args is None:
                # 坏 JSON：不执行、不烧预算，tool 响应回纠错提示让 LLM 重新生成
                bad_json += 1
                result = {"error": _BAD_JSON_TOOL_ERROR}
                _tlog(task_id, "tool", f"{tool_name} -> INVALID JSON args (rejected)",
                      getattr(self, "_current_module", ""))
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", call_id),
                    "content": json.dumps(result, ensure_ascii=False),
                })
                continue
            self._tool_started[call_id] = time.strftime("%Y-%m-%dT%H:%M:%S")
            args = _prepare_args(tool_def, args, self.container, self.workdir)
            if tool_name in ("submit_finding", "record_coverage", "create_vulnerability_report"):
                args["task_id"] = task_id
            if tool_name in ("kb_query", "query_tool_output"):
                args["task_id"] = task_id
            if tool_name == "submit_finding":
                args["target"] = target
                args["target_id"] = resolve_target_id(target, args.get("target_id", ""))
            call_str = json.dumps({"tool": tool_name, "args": args}, ensure_ascii=False)
            warn = _detect_repeating(self.recent_calls, call_str)
            self.recent_calls.append(call_str)

            if tool_def is None:
                result = {"error": f"unknown tool: {tool_name}"}
            else:
                # 命令级安全管控（ARTEX intercept 移植）：deny 拦截 / ask 人工审批 / allow 白名单
                blocked = await intercept_check(tool_name, args, task_id)
                if blocked is None:
                    _fab = self._fabrication_gate(tool_name, args)
                    if _fab is not None:
                        blocked = {"error": _fab}
                if blocked is not None:
                    result = blocked
                else:
                    _tmo = float(cfg_env("HINSE_TOOL_TIMEOUT", "120"))
                    try:
                        result = await asyncio.wait_for(tool_def.handler(**args), timeout=_tmo)
                    except asyncio.TimeoutError:
                        result = {"error": f"tool {tool_name} timeout after {_tmo:.0f}s — 换更快策略(如 nmap 用 -F 或限端口, 别扫全端口)"}
                    except TypeError as e:
                        result = {"error": _arg_error(tool_name, tool_def, e, args)}
                        self._arg_error_streak += 1
                        if self._arg_error_streak >= 2:
                            self.messages.append({"role": "user", "content": (
                                "TOOL ARGUMENTS ERROR — you are omitting required parameters. "
                                "Read each tool's schema carefully and pass ALL required arguments "
                                "in the 'arguments' JSON object. Do not retry the same broken call.")})
                    except Exception as e:
                        result = {"error": f"tool error: {type(e).__name__}: {e}"}
                    else:
                        self._arg_error_streak = 0
            self._tool_ended[call_id] = time.strftime("%Y-%m-%dT%H:%M:%S")
            print(f"[tool] {tool_name} -> {str(result)[:150].replace(chr(10), ' ')}", flush=True)
            if tool_name == "load_skill" and isinstance(result, dict) and "error" not in result:
                newly = self._unlock(str(args.get("name", "")))
                if newly:
                    # 解锁信息前置：大 skill 内容会被 8K 外置截断，后置字段会被吞掉
                    result = {"unlocked_tools": newly,
                              "note": f"tools unlocked, available from next turn: {', '.join(newly)}",
                              **result}
            if warn and "accepted" not in str(result):
                result = {**result, "_warning": warn}

            if tool_name in ("submit_finding", "record_coverage") and "error" not in result:
                self._has_recorded = True
            self.state.tool_calls += 1
            _tlog(task_id, "finding" if tool_name == "submit_finding" else "tool",
                  f"{tool_name} -> {_tool_brief(result)}", getattr(self, "_current_module", ""))
            self.messages.append({
                "role": "tool",
                "tool_call_id": tc.get("id", f"call_{self.state.tool_calls}"),
                "content": _tool_result_content(result, task_id, f"{self._uid}-{call_id}"),
            })
            self._flag_nudge(tool_name, result)
            self._record_raw_result(result)
            self._stuck_recovery(tool_name, warn, result)
            if progress_cb:
                progress_cb({"module": getattr(self, "_current_module", ""), "tool": tool_name,
                             "state": "done", "phase": "exploit", "last_type": "result",
                             "last_message": f"[{getattr(self, '_current_module', '')}] {tool_name} 完成",
                             "msg_count": self.state.turn,
                             "result": str(result)[:800]})
        self._bad_json_bump(bad_json)

    def _bad_json_bump(self, bad_json: int) -> bool:
        """坏 JSON 轮次计数：连续 2 轮坏 JSON 注入双语纠错提示（借 CyberStrikeAI
        tool_args_json_retry 思路，但用 in-loop 纠错代替整 agent 重跑）。返回是否注入了提示。"""
        if bad_json:
            self._bad_json_streak += 1
            if self._bad_json_streak >= 2:
                self.messages.append({"role": "user", "content": _BAD_JSON_REMINDER})
                return True
        else:
            self._bad_json_streak = 0
        return False

    def _brief_snapshot(self) -> str:
        """惰性抓取首条 user 消息快照（≤4000 字符）。上下文压缩会把原始任务配方
        换成占位符——m3-s2 实测 agent 因此'忘了'要重建的命令而空转。重注入用。"""
        if not self._initial_brief:
            try:
                self._initial_brief = str(next(
                    (m.get("content", "") for m in self.messages if m.get("role") == "user"), ""))[:4000]
            except Exception:
                pass
        return self._initial_brief

    def _stuck_recovery(self, tool_name: str, warn, result) -> None:
        """失败自恢复环（通用件，2026-10-28）：两类机械可检的卡死形态。
        ① 连续重复同一调用（_detect_repeating 的 warn 连击）→ 注入重定向+原始简报重注入；
        ② 同一文件 ENOENT 反复出现 → 注入"重建而非重查"提示。
        治 m3-s2（文件缺失 ls/cat 一小时）/m6-s1（15 连发相同 ls）型空转死。"""
        try:
            blob = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
        except Exception:
            blob = str(result)[:5000]
        if not blob:
            blob = ""
        blob = blob[:5000]
        # ① 重复调用连击
        if warn:
            self._repeat_streak += 1
            if self._repeat_streak >= 3 and self._stuck_nudges < 4:
                self._repeat_streak = 0
                self._stuck_nudges += 1
                brief = self._brief_snapshot()
                msg = ("[SYSTEM] STUCK-LOOP DETECTED — 你已连续重复同一工具调用且无进展。停止重复。诊断三选一：\n"
                       "1) 文件缺失？→ 按下方任务简报重跑生成/下载该文件的命令（不是再查一遍）；\n"
                       "2) 命令失败？→ 改一个参数换一种方式重试；\n"
                       "3) 不知道下一步？→ 重读简报按顺序执行下一指令。\n"
                       "下一次工具调用必须与上次不同。\n")
                if brief:
                    msg += f"\n--- ORIGINAL TASK BRIEF (re-injected, 上下文压缩可能已丢失) ---\n{brief}\n--- END BRIEF ---"
                self.messages.append({"role": "user", "content": msg})
        else:
            self._repeat_streak = 0
        # ② 同路径 ENOENT 循环（python/ls/cat 三种报错形态）
        import re as _re
        for line in blob.splitlines():
            if "No such file or directory" in line or "cannot access" in line:
                for m in _re.finditer(r"/[A-Za-z0-9_./*?=-]+", line):
                    p = m.group(0)
                    self._enoent_seen[p] = self._enoent_seen.get(p, 0) + 1
                    if self._enoent_seen[p] >= 2 and p not in self._enoent_nudged and self._stuck_nudges < 4:
                        self._enoent_nudged.add(p)
                        self._stuck_nudges += 1
                        self.messages.append({"role": "user", "content": (
                            f"[SYSTEM] FILE-MISSING LOOP: {p} 已被多次报告不存在——反复检查不会让它出现。"
                            f"按任务简报重跑生成/下载该文件的命令；若简报说它应已预置，报告缺失并改用替代路径。"
                            f"（不要再次检查该文件。）")})
                break  # 每个结果只处理首个 ENOENT 行（同结果多行多为同一根因）

    def _flag_nudge(self, tool_name: str, result) -> None:
        """CTF 提交纪律兜底（2026-10-26）：工具输出里出现 flag 形态（env CTF 前缀模式或
        UUIDv4）时注入"立即 submit_finding"提醒。同一值只提醒一次，单次结果最多提醒 2 个。
        治 m4-s4 型"答案在工具输出里却转去写文件、预算耗尽 0 提交"。"""
        if not getattr(self, "_ctf_flag_watch", False) or tool_name in ("submit_finding", "record_coverage"):
        # getattr：测试常用部分构造的 agent（不走 __init__）
            return
        exempt = self._flag_exempt_set()
        blob = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
        if not blob or len(blob) > 300000:
            if not blob:
                return
            blob = blob[:300000]
        nudged = 0
        for rx in _flag_nudge_patterns():
            for m in rx.findall(blob):
                v = (m[0] if isinstance(m, tuple) and m else m) if not isinstance(m, str) else m
                v = str(v).strip()
                key = v.lower()
                if not v or key in self._flag_nudged or key in self._flag_exempt:
                    continue
                self._flag_nudged.add(key)
                self.messages.append({"role": "user", "content": (
                    f"⚠️ FLAG CANDIDATE DETECTED in tool output: {v}\n"
                    "工具输出里出现了 flag 形态的值。如果它是本任务的目标 flag，"
                    "立即调用 submit_finding 提交（title 简述来源，evidence 粘贴相关输出行）——"
                    "提交是当前最高优先级动作，不要先去写文件、保存脚本或做其他探索。")})
                nudged += 1
                if nudged >= 2:
                    return

    def _flag_exempt_set(self) -> set:
        """任务文本（首 user 消息）里已有的 flag 形态值——nudge 与 fabrication gate 共用豁免
        （那是 desc 给的凭据/情报，m6-s1 实战误伤过）。惰性计算一次。"""
        if getattr(self, "_flag_exempt", None) is not None:
            return self._flag_exempt
        exempt: set = set()
        try:
            first_user = next((m.get("content", "") for m in self.messages
                               if m.get("role") == "user"), "")
            for rx in _flag_nudge_patterns():
                for v in rx.findall(str(first_user)):
                    v = (v[0] if isinstance(v, tuple) and v else v) if not isinstance(v, str) else v
                    if v:
                        exempt.add(str(v).lower())
        except Exception:
            pass
        self._flag_exempt = exempt
        return exempt

    def _record_raw_result(self, result) -> None:
        """记录未截断的原始工具输出（防幻觉 gate 的比对语料）。惰性初始化（测试常部分构造 agent）。"""
        if not hasattr(self, "_raw_tool_outputs"):
            from collections import deque
            self._raw_tool_outputs = deque(maxlen=200)
        blob = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
        if blob:
            self._raw_tool_outputs.append(blob[:200000])

    def _fabrication_gate(self, tool_name: str, args: dict) -> Optional[str]:
        """反幻觉 gate（2026-10-30 Modbus 实弹）：CTF 提交里含 flag 形态但**逐字**不出现在任何
        原始工具输出 → 拒绝。治 qwen 编造从没读到的 FLAG{...} 被 pattern 早停误判 solved。
        至少一个提交的 flag 在原始输出中逐字存在即放行；任务文本(desc)里的值豁免。"""
        if tool_name != "submit_finding" or not getattr(self, "_ctf_flag_watch", False):
            return None
        texts = " ".join(str(v) for v in (args or {}).values()
                         if isinstance(v, (str, int, float)))
        exempt = self._flag_exempt_set()
        flags = []
        for rx in _flag_nudge_patterns():
            for m in rx.findall(texts):
                v = (m[0] if isinstance(m, tuple) and m else m) if not isinstance(m, str) else m
                v = str(v).strip()
                if v and v.lower() not in exempt and v not in flags:
                    flags.append(v)
        if not flags:
            return None
        raws = getattr(self, "_raw_tool_outputs", None)
        if not raws:
            return None  # 还没有任何工具输出（第一步就提交）→ 无从比对，放行
        hay = "\n".join(raws)
        for f in flags:
            if _flag_seen(f, hay):
                return None
        return ("REJECTED — FABRICATION SUSPECTED: the flag string(s) you submitted "
                "(%s) do not appear in any of your actual tool outputs — neither verbatim "
                "nor as a contiguous run of their ASCII/byte values (e.g. register dumps). "
                "You must NEVER invent, reconstruct or guesser-complete a flag. Re-read your "
                "tool outputs and copy the real flag byte-for-byte. If you have not actually "
                "seen the flag in an output, do not submit one — report your honest status "
                "(what you read and where the flag should be)." % ", ".join(flags[:3]))

    async def _exec_tool_calls_stream(self, tool_calls: List[Dict[str, Any]],
                                      task_id: str, target: str) -> AsyncIterator[Dict[str, Any]]:
        bad_json = 0
        for tc in tool_calls:
            fn = tc.get("function", {})
            tool_name = fn.get("name")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = None
            tool_def = get_tool(tool_name)
            call_id = str(tc.get("id") or f"call_{self.state.tool_calls}")
            if args is None:
                bad_json += 1
                result = {"error": _BAD_JSON_TOOL_ERROR}
                _tlog(task_id, "tool", f"{tool_name} -> INVALID JSON args (rejected)",
                      getattr(self, "_current_module", ""))
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", call_id),
                    "content": json.dumps(result, ensure_ascii=False),
                })
                yield {"type": "tool", "content": tool_name, "detail": result}
                continue
            self._tool_started[call_id] = time.strftime("%Y-%m-%dT%H:%M:%S")
            args = _prepare_args(tool_def, args, self.container, self.workdir)
            # task_id 强制注入：LLM 不知道真实 task_id（会填 vuln_class/模块名等错值），
            # 无条件用编排层传入的正确 task_id 覆盖，保证 board 归组/KB 来源标记正确。
            if tool_name in ("submit_finding", "record_coverage", "create_vulnerability_report"):
                args["task_id"] = task_id
            if tool_name in ("kb_query", "query_tool_output"):
                args["task_id"] = task_id
            if tool_name == "submit_finding":
                args["target"] = target
                args["target_id"] = resolve_target_id(target, args.get("target_id", ""))
            call_str = json.dumps({"tool": tool_name, "args": args}, ensure_ascii=False)
            warn = _detect_repeating(self.recent_calls, call_str)
            self.recent_calls.append(call_str)

            if tool_def is None:
                result = {"error": f"unknown tool: {tool_name}"}
            else:
                # 命令级安全管控（ARTEX intercept 移植）：deny 拦截 / ask 人工审批 / allow 白名单
                blocked = await intercept_check(tool_name, args, task_id)
                if blocked is None:
                    _fab = self._fabrication_gate(tool_name, args)
                    if _fab is not None:
                        blocked = {"error": _fab}
                if blocked is not None:
                    result = blocked
                else:
                    _tmo = float(cfg_env("HINSE_TOOL_TIMEOUT", "120"))
                    try:
                        result = await asyncio.wait_for(tool_def.handler(**args), timeout=_tmo)
                    except asyncio.TimeoutError:
                        result = {"error": f"tool {tool_name} timeout after {_tmo:.0f}s — 换更快策略(如 nmap 用 -F 或限端口, 别扫全端口)"}
                    except TypeError as e:
                        result = {"error": _arg_error(tool_name, tool_def, e, args)}
                        self._arg_error_streak += 1
                        if self._arg_error_streak >= 2:
                            self.messages.append({"role": "user", "content": (
                                "TOOL ARGUMENTS ERROR — you are omitting required parameters. "
                                "Read each tool's schema carefully and pass ALL required arguments "
                                "in the 'arguments' JSON object. Do not retry the same broken call.")})
                    except Exception as e:
                        result = {"error": f"tool error: {type(e).__name__}: {e}"}
                    else:
                        self._arg_error_streak = 0
            self._tool_ended[call_id] = time.strftime("%Y-%m-%dT%H:%M:%S")
            print(f"[tool] {tool_name} -> {str(result)[:150].replace(chr(10), ' ')}", flush=True)
            if tool_name == "load_skill" and isinstance(result, dict) and "error" not in result:
                newly = self._unlock(str(args.get("name", "")))
                if newly:
                    # 解锁信息前置：大 skill 内容会被 8K 外置截断，后置字段会被吞掉
                    result = {"unlocked_tools": newly,
                              "note": f"tools unlocked, available from next turn: {', '.join(newly)}",
                              **result}
            if warn and "accepted" not in str(result):
                result = {**result, "_warning": warn}

            if tool_name in ("submit_finding", "record_coverage") and "error" not in result:
                self._has_recorded = True
            self.state.tool_calls += 1
            _tlog(task_id, "finding" if tool_name == "submit_finding" else "tool",
                  f"{tool_name} -> {_tool_brief(result)}", getattr(self, "_current_module", ""))
            self.messages.append({
                "role": "tool",
                "tool_call_id": tc.get("id", f"call_{self.state.tool_calls}"),
                "content": _tool_result_content(result, task_id, f"{self._uid}-{call_id}"),
            })
            self._flag_nudge(tool_name, result)
            self._record_raw_result(result)
            self._stuck_recovery(tool_name, warn, result)
            yield {"type": "tool", "content": tool_name, "detail": result}
        if self._bad_json_bump(bad_json):
            yield {"type": "text", "content": _BAD_JSON_REMINDER}

    def _case_tool_calls(self) -> List[Dict[str, Any]]:
        pending: Dict[str, Dict[str, Any]] = {}
        completed: List[Dict[str, Any]] = []
        for message in self.messages:
            if message.get("role") == "assistant" and message.get("tool_calls"):
                for tc in message["tool_calls"]:
                    fn = tc.get("function", {})
                    call_id = str(tc.get("id") or "")
                    if call_id:
                        pending[call_id] = {
                            "name": fn.get("name", ""),
                            "args": _tool_args(tc),
                        }
            elif message.get("role") == "tool":
                call_id = str(message.get("tool_call_id") or "")
                call = pending.pop(call_id, None)
                if not call:
                    continue
                result = message.get("content", "")
                try:
                    parsed_result = json.loads(result)
                except (TypeError, json.JSONDecodeError):
                    parsed_result = result
                call["result"] = parsed_result
                call["status"] = "ok" if isinstance(parsed_result, dict) and "error" not in parsed_result else "error"
                call["started_at"] = self._tool_started.get(call_id, time.strftime("%Y-%m-%dT%H:%M:%S"))
                call["ended_at"] = self._tool_ended.get(call_id, time.strftime("%Y-%m-%dT%H:%M:%S"))
                completed.append(call)
        # 已完成（拿到 tool 结果）按执行顺序返回；未被 tool 结果配对的（如 compaction 截断）
        # 保留在末尾，避免轨迹丢调用
        completed.extend(pending.values())
        return completed

    def _case_db_rows(self) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        conn = _conn()
        try:
            findings = [dict(r) for r in conn.execute(
                "SELECT id,target,title,location,severity,vuln_class,poc,evidence,status,dedup_key "
                "FROM findings WHERE task_id=?", (getattr(self, "last_task_id", ""),)
            ).fetchall()]
            coverage = [dict(r) for r in conn.execute(
                "SELECT id,surface,risk_area,outcome,evidence FROM coverage WHERE task_id=?",
                (getattr(self, "last_task_id", ""),),
            ).fetchall()]
        finally:
            conn.close()
        return findings, coverage

    def _inject_budget_notice(self):
        limit = _max_turns(self)
        pct = self.state.tool_calls / limit
        # (A) 进度自查：每 5 轮一次，仅在"还没记录过任何 finding"时催（治"过度验证不收口"）
        if not self._has_recorded and self.state.tool_calls >= 5 and self.state.tool_calls % 5 == 0:
            key = f"_chk{self.state.tool_calls}"
            if not getattr(self.state, key, False):
                setattr(self.state, key, True)
                self.messages.append({"role": "user", "content":
                    "PROGRESS CHECK: you have recorded ZERO findings so far. A single proof confirms a vuln "
                    "(SQL error, one UNION row, reflected payload, command output). If you have shown ANY vuln "
                    "working, call submit_finding + record_coverage NOW — do not hoard. If still exploring, "
                    "stop and record what you have."})
        # (B) 预算阈值强制收口（error-based/UNION/时间盲注 任一证据即算确认）
        for t, key in ((0.5, "_rec50"), (0.75, "_rec75"), (0.9, "_rec90")):
            if pct >= t and not getattr(self.state, key, False):
                setattr(self.state, key, True)
                if t < 0.75:
                    msg = (f"**~{int(pct*100)}% of turn budget used. STOP exploring new vectors. "
                           "A single proof (SQL error, UNION data, time delay, OOB) counts as CONFIRMED. "
                           "For every vuln you've already shown working: call submit_finding AND record_coverage "
                           "NOW. Only test more if you have found nothing yet.")
                elif t < 0.9:
                    msg = (f"**{int(pct*100)}% of budget used. Record what you have: for each confirmed vuln "
                           "call submit_finding (title,poc,evidence,severity,vuln_class) + record_coverage "
                           "(outcome=reported). For every surface you tested, record_coverage with the honest "
                           "outcome (ruled_out/no_issue_found REQUIRE evidence). Then stop new exploitation.")
                else:
                    msg = (f"**CRITICAL: ~{int(pct*100)}% of budget used. Cease ALL testing immediately. "
                           "Record EVERYTHING now: submit_finding for each confirmed vuln, record_coverage for "
                           "every surface tested. Then call done. Do NOT start any new exploitation.")
                    # CTF 模式：特别催 flag 提交
                    if getattr(self, "_module", "") == "objective" or "CTF" in (self._task_text or ""):
                        msg += ("\n⚠️ CTF MODE: if you have found ANY flag-like string (HTB{...}, SEKAI{...}, "
                                "gctf{...}, hkcert22{...}, flag{...}), call submit_finding IMMEDIATELY with the "
                                "flag as evidence. Do NOT wait until you are 100% sure — submit what you have NOW.")
                self.messages.append({"role": "user", "content": msg})

    def _fail(self, err: str) -> Dict[str, Any]:
        return {"agent": "RedBee", "error": err, "turns": self.state.turn, "tool_calls": self.state.tool_calls}

    async def _final_wrapup(self, runtime, task_id: str, target: str) -> str:
        """预算/轮次耗尽时的强制收口总结（借 CyberStrikeAI"max_iterations 到点自动总结"）。
        LLM 优先；LLM 挂死/超时（正是要兜底的场景）降级为 DB 机械总结，保证总有结论。
        收口前自动扫描对话提取 flag 并补提交（治 agent 找到 flag 但没 submit 就到点）。"""
        try:
            self._extract_and_submit_flags(task_id)
        except Exception as e:
            print(f"[wrapup] flag 提取失败: {str(e)[:100]}", flush=True)
        try:
            self._compact_messages()
            msgs = list(self.messages) + [{"role": "user", "content": _WRAPUP_PROMPT}]
            msg = await asyncio.wait_for(
                self._chat(msgs, max_tokens=1024, runtime=runtime), timeout=120)
            content = (msg.get("content") or "").strip()
            if content and not msg.get("tool_calls"):
                return content[:4000]
        except Exception as e:
            print(f"[wrapup] LLM 收口失败，降级机械总结: {str(e)[:100]}", flush=True)
        return self._mechanical_summary()

    def _mechanical_summary(self) -> str:
        """LLM 不可用时的机械收口：从 DB findings/coverage 生成结构化总结。"""
        try:
            findings, coverage = self._case_db_rows()
        except Exception:
            return "FINAL SUMMARY: budget/turn limit reached; findings/coverage unavailable."
        lines = ["FINAL SUMMARY (turn/time budget exhausted):"]
        lines.append(f"- Findings recorded: {len(findings)}")
        for f in findings[:15]:
            lines.append(f"  [{f.get('severity', '?')}/{f.get('status', '?')}] {f.get('title', '?')}")
        outcomes: Dict[str, int] = {}
        for c in coverage:
            k = str(c.get("outcome", "?"))
            outcomes[k] = outcomes.get(k, 0) + 1
        if outcomes:
            lines.append("- Coverage: " + ", ".join(f"{k}={v}" for k, v in sorted(outcomes.items())))
        lines.append("- Remaining budget did not allow further testing; untested surfaces stay open.")
        return "\n".join(lines)[:4000]

    # ---- CTF wrapup 自动 flag 提取（2026-10-17）----
    _FLAG_RE = re.compile(
        r"(?:HTB|FLAG|GCTF|SEKAI|CTF|picoCTF|hkcert2{0,2}|HKN|Glacier|DUCTF|flag)\{[^}\s]{4,}\}",
        re.IGNORECASE,
    )

    def _extract_and_submit_flags(self, task_id: str) -> None:
        """收口时扫描对话中出现过的 flag 模式，若 findings 为空则自动 submit_finding。
        治"agent 找到了 flag 但没调 submit_finding 就到点"的系统性丢分。"""
        try:
            findings, _ = self._case_db_rows()
            if findings:
                return  # 已有 finding，不用补
        except Exception:
            pass
        seen: set = set()
        for msg in self.messages:
            content = msg.get("content") or ""
            if not content:
                continue
            for m in self._FLAG_RE.finditer(content):
                flag = m.group(0)
                if flag in seen:
                    continue
                seen.add(flag)
                # 过滤明显的假 flag（占位/示例）
                low = flag.lower()
                if any(x in low for x in ("this_is_fake", "example", "placeholder", "xxxx", "your_flag")):
                    continue
                # 直接调 submit_finding 工具函数
                try:
                    from agents.tools import tool_submit_finding
                    import asyncio as _aio
                    result = _aio.get_event_loop().run_until_complete(
                        tool_submit_finding(
                            title=f"[auto-extracted] CTF flag {flag[:20]}...",
                            poc=f"Flag extracted from agent conversation: {flag}",
                            evidence=flag,
                            asset=self.last_task_id or "",
                            severity="high", vuln_class="ctf_flag",
                            confidence="high", task_id=task_id,
                        )
                    )
                    if result.get("accepted"):
                        print(f"[wrapup] auto-submitted flag: {flag[:30]}...", flush=True)
                except Exception as e:
                    # asyncio 可能已在运行中，用 create_task
                    try:
                        from agents.tools import tool_submit_finding
                        asyncio.ensure_future(tool_submit_finding(
                            title=f"[auto-extracted] CTF flag {flag[:20]}...",
                            poc=f"Flag extracted from agent conversation: {flag}",
                            evidence=flag,
                            asset=self.last_task_id or "",
                            severity="high", vuln_class="ctf_flag",
                            confidence="high", task_id=task_id,
                        ))
                        print(f"[wrapup] auto-submitted flag (async): {flag[:30]}...", flush=True)
                    except Exception:
                        pass

    def _finalize(self, task_id: str, target: str, runtime: ModelRuntime) -> Dict[str, Any]:
        findings, coverage = self._case_db_rows()
        tool_calls = self._case_tool_calls()
        evidence_by_id: Dict[str, str] = {}
        evidence_refs: List[str] = []
        for finding in findings:
            evidence = _case_redact(finding.get("evidence", ""))
            if not evidence:
                continue
            evidence_id = f"ev-{hash_text(evidence)[:16]}"
            evidence_by_id[evidence_id] = evidence
            evidence_refs.append(evidence_id)
        snapshot = build_inhouse_case_snapshot(
            task_id=task_id,
            target=target,
            target_id=resolve_target_id(target, ""),
            model=runtime.model,
            runtime_id=runtime.runtime_id,
            findings=findings,
            coverage=coverage,
            tool_calls=tool_calls,
            llm_turns=self.state.turn,
            evidence_refs=evidence_refs,
            summary=getattr(self, "final_summary", "") or "",
        )
        try:
            case_id = store_inhouse_case(snapshot, evidence_by_id)
        except Exception as exc:
            return {
                "agent": "RedBee", "model": runtime.model,
                "runtime_id": runtime.runtime_id, "task_id": task_id,
                "target": target,
                "trajectory": {"turns": self.state.turn, "tool_calls": self.state.tool_calls},
                "case_id": None, "case_snapshot": None,
                "case_capture_error": str(exc),
            }
        return {
            "agent": "RedBee", "model": runtime.model,
            "runtime_id": runtime.runtime_id, "task_id": task_id,
            "target": target,
            "trajectory": {"turns": self.state.turn, "tool_calls": self.state.tool_calls},
            "case_id": case_id,
            "case_snapshot": snapshot.model_dump(),
        }

# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _openai_tool_call_obj(tc: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize OpenAI tool_calls entry for message replay."""
    return {
        "id": tc.get("id", ""),
        "type": "function",
        "function": {
            "name": tc.get("function", {}).get("name", ""),
            "arguments": tc.get("function", {}).get("arguments", "{}"),
        },
    }

_WRAPUP_PROMPT = (
    "FINAL WRAP-UP REQUIRED: the turn/time budget is exhausted — no further tool calls will be processed. "
    "Write the final summary NOW as plain text, no tools. Structure: "
    "1) CONFIRMED — each working vulnerability with its proof in one line; "
    "2) RULED OUT — surfaces tested with negative evidence; "
    "3) UNTESTED — what the budget did not allow; "
    "4) One-sentence overall conclusion. "
    "Under 250 words. 直接输出总结文本，不要再调用任何工具。"
)


_BAD_JSON_TOOL_ERROR = (
    "tool arguments is not valid JSON — the call was NOT executed. "
    "Regenerate this tool call with a complete, parseable JSON object: double-quoted keys, "
    "matched braces, no trailing commas, no truncated values. "
    "参数不是合法 JSON，本次调用未执行；请重新生成完整可解析的 JSON 参数对象。"
)
_BAD_JSON_REMINDER = (
    "[System] Your previous tool call(s) used invalid JSON in function.arguments and were rejected. "
    "Regenerate with strictly valid JSON objects only (double-quoted keys, matched braces, "
    "no trailing commas, no truncation). "
    "上一次工具调用的 arguments 不是合法 JSON 已被拒绝。请重新生成：每个 tool call 的 arguments "
    "必须是完整、可解析的 JSON 对象字符串（键名双引号、括号配对、无尾逗号、不截断）。"
)

_REPEAT_WINDOW = 5
_REPEAT_THRESHOLD = 3

# CTF 工具流 flag 识别（_flag_nudge 用）：env CTF 前缀模式 + UUIDv4，惰性编译（env 热读）
_FLAG_NUDGE_CACHE: Optional[List["re.Pattern"]] = None

def _flag_nudge_patterns() -> List["re.Pattern"]:
    global _FLAG_NUDGE_CACHE
    if _FLAG_NUDGE_CACHE is None:
        pats: List["re.Pattern"] = []
        env_pat = (cfg_env("PIMETA_CTF_FLAG_PATTERN") or "").strip()
        if env_pat:
            try:
                pats.append(re.compile(env_pat))
            except re.error:
                pass
        # UUIDv4（nilgiri 等 UUID-flag 靶场；version 位=4，variant 位 8/9/a/b）
        pats.append(re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I))
        _FLAG_NUDGE_CACHE = pats
    return _FLAG_NUDGE_CACHE

def _flag_seen(flag: str, hay: str) -> bool:
    """flag 是否"被看到"：①逐字出现，或 ②其字节值作为连续整数序列出现在输出里
    （寄存器/字节 dump 解码场景：agent 读到 [70,76,65,71,123,...] 在 LLM 里解成
    FLAG{...}——逐字不在输出，但字节序列在 → 合法，不该误杀）。"""
    if flag in hay:
        return True
    target = [ord(c) for c in flag]
    n = len(target)
    if n < 4 or n > 512:
        return False
    for raw in (x for x in hay.split("\n") if any(ch.isdigit() for ch in x)):
        if len(raw) > 1_000_000:
            continue  # 超长行跳过字节序列扫描（防病态慢；逐字检查已覆盖）
        nums = []
        for m in re.finditer(r"0x[0-9a-fA-F]{1,4}\b|\b\d{1,5}\b", raw):
            tok = m.group(0)
            try:
                nums.append(int(tok, 16) if tok.lower().startswith("0x") else int(tok))
            except ValueError:
                continue
        if len(nums) < n:
            continue
        first = target[0]
        for i in range(len(nums) - n + 1):
            if nums[i] == first and nums[i:i + n] == target:
                return True
    return False

def _detect_repeating(recent: List[str], tool_call_str: str) -> Optional[str]:
    if len(recent) >= _REPEAT_WINDOW:
        same = sum(1 for r in recent[-_REPEAT_WINDOW:]
                   if _norm(tool_call_str) == _norm(r))
        if same >= _REPEAT_THRESHOLD:
            return ("You have called the same tool with nearly identical arguments "
                    f"{same} times. Stop repeating. Either: (a) the issue is not "
                    "vulnerable, (b) try a different approach, or (c) declare it "
                    "ruled_out and move on.")
    return None

def _norm(s: str) -> str:
    return re.sub(r'\s+', ' ', s.strip().lower())


def _tool_brief(result) -> str:
    """工具结果摘要（执行日志一行用）。"""
    try:
        if isinstance(result, dict):
            if "error" in result:
                return "ERROR " + str(result["error"])[:160]
            if "accepted" in result:
                return f"accepted={result.get('accepted')} id={result.get('id', '')}"
            if "status" in result:
                return f"HTTP {result.get('status')} ({len(str(result.get('text') or ''))}B)"
            if "injectable_params" in result:
                return f"injectable={result.get('injectable_params')}"
        return str(result)[:160].replace("\n", " ")
    except Exception:
        return str(result)[:160]

class _State:
    def __init__(self):
        self.todos: List[Dict[str, Any]] = []
        self.turn = 0
        self.tool_calls = 0
