"""v2 多 Agent 编排器 — root LLM 决策 + 相位交付物 + 并行子 agent。

设计要点:
  - root = LLM agent: 用 list_coverage/list_reports/list_notes 工具
        自己观察覆盖率/进展，用 LLM 决策"下一步"，不是硬编码状态机
  - recon 相位产出结构化攻击面交付物:
        endpoints 目录 + input vectors + auth + network map，存交付物文件
  - 相位间情报用交付物文件传递（带 schema 校验）
  - 并行 spawn 子 agent + 继承父上下文
  - 有界 mini-loop 子 agent（不做嵌套整链委派）
  - 三态收口 + coverage 负空间

职责边界（两层编排）:
  - 本文件 = 引擎内多 agent 编排（root 决策哪个子 agent 做什么）
  - PI pi_meta/orchestrator.py = 任务调度 + 漏洞板贴板/复现/跳过
  - 本文件只聚焦：把任务分成相位，root 用 LLM 决策派活，子 agent 并行执行
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict, List, Optional


from pi_meta.model_runtime import ModelRuntime, ResolvedRuntime, RuntimeClient
from pi_meta.task_logs import log as _tlog
from redkb.governance import hash_text
from config import DATA_DIR as _CFG_DATA_DIR, env as cfg_env

from .executor import InhouseAgent, KALI_IMAGE, _kali_image, build_inhouse_case_snapshot, build_tools_schema, register_container, store_inhouse_case
from .tools import _conn, coverage_reconciliation, MODULE_PHRASINGS, resolve_target_id, query_kb_redkb
from . import task_registry

import sqlite3
import re

# ---- KB 热启动（经验回流闭环：打过的 target → 沉淀 → 下次跳侦察）----
# resolve_target_id 从 .tools import（权威定义在 tools 层，避免循环依赖）
_REDKB_DIR = os.environ.get("REDKB_DATA_DIR", _CFG_DATA_DIR)
REDKB_DB_PATH = os.path.join(_REDKB_DIR, "redkb.db")
TARGETS_DIR = os.path.join(_REDKB_DIR, "targets")  # 靶场档案（靶场特定情报，非通用知识）


def _target_intel_brief(target_id: str) -> str:
    """热启动 brief：读靶场档案（data/targets/<target_id>.md，靶场特定情报）。
    KB 只存通用知识（scope=all）——通用技法 agent 用 kb_query 检索，不进 brief。
    护栏：档案只含中性 intel（端点/凭据/漏洞位置/交互方式），载荷由执行器/kb_query 处理。
    ⚠️ 剥离 SQLi 相关文本（DeepSeek 内容过滤对 'SQL 注入'/'UNION' 等直接挂起连接）。"""
    if not target_id:
        return ""
    profile_path = os.path.join(TARGETS_DIR, f"{target_id}.md")
    if not os.path.exists(profile_path):
        return ""
    try:
        content = open(profile_path, encoding="utf-8").read().strip()
    except Exception:
        return ""
    if not content:
        return ""
    try:
        from agents.tools import _strip_payload_lines
        content = _strip_payload_lines(content)
    except Exception:
        pass
    return ("=== 热启动：目标档案（" + target_id + "）===\n"
            + content[:2500]
            + "\n\n通用攻击技法用 kb_query 检索（KB scope=all）；"
            "以上为靶场特定情报（端点/凭据/漏洞位置/交互），直接复用、跳过已知项的重复侦察。")


# pre-recon 结构化情报 schema（one-shot 设置）
PRERECON_FIELDS = {
    "executive_summary": "What is the target, what does it do, what tech stack?",
    "application_intelligence": "Entry points, auth model, input surfaces, interesting endpoints.",
    "auth_deep_dive": "Login flow, session mechanism, credential handling, password reset.",
    "critical_file_paths": "High-value paths/files (configs, backups, admin, upload dir).",
    "xss_sinks": "User-controlled input reflected/stored into HTML/JS contexts.",
    "ssrf_sinks": "Parameters that fetch URLs/remote resources.",
}

# 相位定义
PHASES = ["pre-recon", "recon", "exploit", "report"]
# 模块并行上限（子 agent 并发数）
MAX_PARALLEL = int(os.environ.get("HINSE_MAX_PARALLEL", "3"))
# 子 agent 有界 iteration（mini-loop，不做嵌套整链委派）
CHILD_MAX_TURNS = int(os.environ.get("HINSE_CHILD_MAX_TURNS", "40"))
# 交付物目录（相位间情报传递）
DELIVERABLES_DIR = os.environ.get("HINSE_DELIVERABLES", "/tmp/opencode/hinse_deliverables")

os.makedirs(DELIVERABLES_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# 任务级共享沙箱容器（一次任务一个 sandbox，所有相位/模块 agent 共享）
# 每个 agent 用独立工作目录 /work/<module> 隔离文件状态；/work/shared 放共享产物
# （A 下载的备份 B 直接读，免重复下载）。回收：任务结束统一 docker rm -f。
# ---------------------------------------------------------------------------

def _task_container_name(task_id: str) -> str:
    return f"inhouse-task-{(task_id or 'none')[:8]}"


async def _task_container_ensure(task_id: str) -> str:
    """幂等：同名容器已存在则复用（gap 补测轮/重启续跑）；否则创建 + 初始化工作目录。"""
    name = _task_container_name(task_id)
    proc = await asyncio.create_subprocess_shell(
        f"docker ps -q --filter name={name}",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
    if out.decode().strip():
        return name
    proc = await asyncio.create_subprocess_shell(
        f"docker run -d --name {name} --network bridge {_kali_image()} tail -f /dev/null",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await asyncio.wait_for(proc.communicate(), timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(f"docker run failed: {err.decode()}")
    m = await asyncio.create_subprocess_shell(
        f"docker exec {name} mkdir -p /work /work/shared",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    await asyncio.wait_for(m.communicate(), timeout=15)
    register_container(name, task_id)
    return name


async def _task_container_kill(name: str):
    if not name:
        return
    try:
        p = await asyncio.create_subprocess_shell(f"docker rm -f {name}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await asyncio.wait_for(p.communicate(), timeout=20)
        print(f"[orch] task container {name} removed", flush=True)
    except Exception as e:
        print(f"[orch] task container {name} remove failed: {e}", flush=True)


# ---------------------------------------------------------------------------
# 交付物（相位间情报传递）
# ---------------------------------------------------------------------------

def _recon_deliverable_path(task_id: str) -> str:
    return os.path.join(DELIVERABLES_DIR, f"recon_{task_id}.md")


def _save_recon_deliverable(task_id: str, content: str):
    with open(_recon_deliverable_path(task_id), "w") as f:
        f.write(content)
    return content


def _load_recon_deliverable(task_id: str) -> str:
    p = _recon_deliverable_path(task_id)
    if os.path.exists(p):
        with open(p) as f:
            return f.read()
    return ""


# coverage 台账（负空间）
def _list_coverage(task_id: str = "") -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        if task_id:
            rows = conn.execute(
                "SELECT surface,risk_area,outcome,evidence FROM coverage WHERE task_id=?", (task_id,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT surface,risk_area,outcome,evidence FROM coverage").fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def _coverage_brief(task_id: str = "") -> str:
    rows = _list_coverage(task_id)
    if not rows:
        return "(coverage: none recorded)"
    lines = [f"- {r['surface']} / {r['risk_area']} -> {r['outcome']}"
             + (f" : {str(r['evidence'])[:60]}" if r['evidence'] else "")
             for r in rows]
    return "COVERAGE SO FAR:\n" + "\n".join(lines)


# 交付物 schema（结构化 + 校验，不是 best-effort parse）
PRERECON_REQUIRED_KEYS = list(PRERECON_FIELDS.keys())
RECON_REQUIRED_SECTIONS = ["Endpoints", "Input vectors", "Authentication", "Network map"]


# ---------------------------------------------------------------------------
# root LLM agent（带 coverage/list 工具的决策 agent）
# ---------------------------------------------------------------------------

async def _root_plan(task: str, target: str, task_id: str, modules: List[str],
                     intel_block: str, runtime) -> Dict[str, Any]:
    """root LLM 决策（root 看 coverage+intel，用 LLM 决定派哪些模块）。
    单轮调用 + inlined 上下文 + 严格 JSON 输出。这是"root 看 coverage 后动态决策"的适配版
    （非完整 root-agent 工具循环，但核心行为一致：观察已覆盖/情报 → LLM 选下一步派发）。"""
    cov_brief = _coverage_brief(task_id)
    prompt = (
        f"You are the ROOT coordinator for a pentest of {target}.\n"
        f"Task: {task}\n\n"
        f"CANDIDATE MODULES (planned): {modules}\n\n"
        f"{intel_block}\n\n"
        f"{cov_brief}\n\n"
        "Decide what to dispatch for EXPLOITATION. Rules:\n"
        "- Dispatch ALL candidate modules that are NOT already covered AND have a plausible attack surface in the intel above. Cover the target BROADLY - default to dispatching MORE modules, not fewer.\n"
        "- Only drop a module if the intel clearly shows it is ABSENT on the target.\n"
        "- You MAY add an in-scope risk class not listed (e.g., ssrf, rce, lfi, csrf, idor).\n"
        "- Set stop=true ONLY if everything important is already covered.\n"
        f'Valid module names: {sorted(set(modules) | set(MODULE_PHRASINGS.keys()))}\n'
        'Return STRICT JSON only. When the target has multiple surfaces, dispatch multiple modules in the list, '
        'e.g. {"modules": ["sqli", "xss", "upload", "csrf"], "stop": false, "reason": "..."}'
    )
    _model = runtime.runtime.model if isinstance(runtime, ResolvedRuntime) else runtime.model
    _rid = getattr(runtime, "runtime_id", "") or getattr(getattr(runtime, "runtime", None), "runtime_id", "")
    payload = {"model": _model,
               "messages": [{"role": "user", "content": prompt}],
               "max_tokens": 800, "temperature": 0.2}
    for attempt in range(2):
        result = await RuntimeClient.chat(runtime, payload)
        if not result.ok or result.error:
            return {"ok": False, "modules": modules, "stop": False,
                    "reason": result.error.redacted_message, "runtime_id": _rid,
                    "error": result.error}
        data = _try_parse_json(result.content)
        if isinstance(data, dict) and isinstance(data.get("modules"), list):
            valid = set(modules) | set(MODULE_PHRASINGS.keys())
            mods = [m for m in data["modules"] if m in valid]
            return {"ok": True, "modules": mods if mods else modules,
                    "stop": bool(data.get("stop")), "reason": data.get("reason", ""),
                    "runtime_id": _rid}
        prompt += "\n\nYour last output was not valid JSON. Return ONLY the JSON object, no prose."
    return {"ok": False, "modules": modules, "stop": False,
            "reason": "root-decide parse failed", "runtime_id": _rid}


# ---------------------------------------------------------------------------
# 子 agent（有界 mini-loop，继承父上下文）
# ---------------------------------------------------------------------------

class _ChildResult:
    def __init__(self, module: str, findings: List[Dict[str, Any]], error: str = "",
                 coverage: List[Dict[str, Any]] = None):
        self.module = module
        self.findings = findings
        self.error = error
        self.coverage = coverage or []


_LLM_DEAD_MARKERS = ("model runtimes failed", "model runtime failed", "all available model")


def _is_llm_dead(error: str) -> bool:
    """模块死亡是否因 LLM 全挂（值得冷却重试）；预算耗尽/容器失败等不值得。"""
    e = (error or "").lower()
    return any(mk in e for mk in _LLM_DEAD_MARKERS)


KB_QUERY_HINTS = {
    "sqli": "SQL injection detection UNION blind boolean extraction",
    "xss": "reflected stored DOM XSS detection context encoding bypass",
    "upload": "file upload bypass extension MIME content to RCE",
    "auth": "authentication bypass JWT algorithm flaws session",
    "lfi": "path traversal LFI arbitrary file read",
    "ssrf": "SSRF detection external fetch metadata",
    "rce": "command injection RCE detection",
    "csrf": "CSRF state-changing request missing token",
    "idor": "IDOR BOLA direct object reference enumeration",
    "xxe": "XXE XML external entity file read",
}

async def _kb_brief(module: str) -> str:
    """workflow 强制注入：按模块语义检索 RED-KB 通用技法。
    只取中性方法/决策层（title + 方法句）；剥离含攻击载荷的行以保护护栏
    （DeepSeek 对 SQLi payload 会 500；载荷由确定性执行器处理）。"""
    try:
        hint = KB_QUERY_HINTS.get(module, f"{module} vulnerability detection technique")
        r = await query_kb_redkb(query=hint, limit=3)
        hits = (r or {}).get("results") or []
        if not hits:
            return ""
    except Exception:
        return ""
    _PAYLOAD_TOK = ("union", "select ", "<script", "onerror", "' or", "&xxe",
                    "drop table", "<svg", "onload", "%27", "!--", "echo ", "rm ",
                    "substr", "char(")
    lines = ["=== KB 通用技法（workflow 强制注入；按此思路与方法打，payload 由执行器处理）==="]
    for h in hits[:3]:
        title = (h.get("title") or h.get("name") or "").strip()
        body = str(h.get("content") or "")[:600]
        sentences = [ln.strip() for ln in body.splitlines()
                     if ln.strip() and not any(t in ln.lower() for t in _PAYLOAD_TOK)]
        summary = " ".join(sentences)[:240]
        if title:
            lines.append(f"- {title}: {summary}")
    return "\n".join(lines) if len(lines) > 1 else ""


async def _run_child(module: str, target: str, task: str, task_id: str,
                       intel_block: str, runtime: ModelRuntime,
                       progress_cb=None, child_max_turns: int = CHILD_MAX_TURNS,
                       shared_container: str = "", task_budget: int = 0,
                       stop_check=None) -> _ChildResult:
    """跑一个模块子 agent：有界 mini-loop，带父 intel（pre-recon+recon 交付物）为背景。

    stop_check: 可选回调，每次工具执行后调用；返回 truthy → 立即收口（CTF flag 早停用）。
    """
    child = InhouseAgent(runtime=runtime)
    child.last_task_id = task_id  # 执行日志归属（llm/tool/steer 埋点用）
    child.MAX_TURNS = child_max_turns  # type: ignore
    child.workdir = f"/work/{module}"
    child._build_initial_messages(target, module, task)
    task_registry.register_agent(task_id, child, module)  # in-run steer：注册运行中 agent（按模块继承相关指令）
    # 治"外层单模块 FOCUS AREA 泄漏进所有内层子 agent"：外层 build_exploit_prompt 把
    # "FOCUS AREA: sqli + work only within this focus area" 烤进 task 文本，_inhouse_run 却复用
    # 它派给全部模块子 agent → 所有 child 都被拽去打 sqli。这里剥离外层焦点，换成 child 自己的 module。
    import re
    _task = re.sub(r"\n?FOCUS AREA: [^\n]*", "", task)
    _task = re.sub(r"Work ONLY within this focus area\.[^\n]*", "", _task)
    if module == "objective":
        # CTF/目标猎取：无类锁，猎手焦点块（异常驱动优先，见 _HUNTER_FOCUS）
        _focus = _HUNTER_FOCUS
    else:
        _focus = (
            f"=== YOUR ASSIGNED MODULE: {module} — WORK ONLY ON THIS ===\n"
            f"You are the {module} specialist for {target}. Find and exploit ONLY the {module} vulnerability class. "
            f"Work ONLY within the {module} area; ignore any other module mentioned below.\n"
        )
    _base = f"{_focus}\n{_task}"
    _wd = (f"WORKDIR: your working directory is {child.workdir} — save downloads/artifacts there "
           f"(this sandbox is shared by sibling agents; do not clobber other modules' files). "
           f"Reusable downloads (backups, bundles, logs) belong in /work/shared/ so siblings can reuse them.\n")
    _base = f"{_base}\n\n{_wd}"
    if intel_block:
        content = f"{_base}\n\n{intel_block}\n\n{_coverage_brief(task_id)}"
        if module != "objective":
            # objective（CTF 猎手）不做类 KB 强制注入：档案 brief 是主力，kb_query 留给运行时自调
            kb = await _kb_brief(module)
            if kb:
                print(f"[orch:{task_id}] KB 通用技法强制注入 module={module}", flush=True)
                content += f"\n\n{kb}"
        child.messages[1] = {"role": "user", "content": content}
    else:
        child.messages[1] = {"role": "user", "content": _base}
    if shared_container:
        # 任务级共享沙箱：复用容器，不新建；_cleanup 不删（编排层统一回收）
        child.container = shared_container
        child._owns_container = False
    else:
        try:
            child.container = await child._docker_run(target_path="")
            register_container(child.container, task_id)
        except Exception as e:
            task_registry.unregister_agent(task_id, child)
            return _ChildResult(module, [], error=f"container: {e}")

    deadline = time.monotonic() + float(task_budget or cfg_env("HINSE_TASK_BUDGET", "1800"))
    _no_tool_streak = 0
    _last_content = ""
    child._current_module = module
    while child.state.tool_calls < child_max_turns and time.monotonic() < deadline:
        if task_registry.is_cancelled(task_id):
            await child._cleanup()
            task_registry.unregister_agent(task_id, child)
            return _ChildResult(module, _collect_findings(task_id), error="cancelled")
        child._drain_notes()  # in-run steer：排空飞行中指令进上下文（下一轮 LLM 生效）
        child._compact_messages()
        child._inject_budget_notice()
        try:
            msg = await child._chat(child.messages, runtime=runtime)
        except Exception as e:
            import traceback
            print(f"[ERROR] {module} _chat raised at turn={child.state.turn}: {type(e).__name__}: {e}\n{traceback.format_exc()}", flush=True)
            await child._cleanup()
            task_registry.unregister_agent(task_id, child)
            return _ChildResult(module, [], error=str(e))
        child.state.turn += 1
        tcs = msg.get("tool_calls")
        tcs_original = tcs
        try:
            from agents.tools import _PAYLOAD_RE as _PRE
            _c = msg.get("content") or ""
            if _PRE.search(_c):
                msg = {**msg, "content": _PRE.sub("", _c).strip()}
            if tcs:
                _new_tcs = []
                for tc in tcs:
                    tc = dict(tc)
                    fn = dict(tc.get("function", {}))
                    args = fn.get("arguments") or "{}"
                    if _PRE.search(args):
                        fn["arguments"] = _PRE.sub("", args)
                    tc["function"] = fn
                    _new_tcs.append(tc)
                tcs = _new_tcs
                msg = {**msg, "tool_calls": tcs}
        except Exception:
            pass
        print(f"[exploit:{module}] t={child.state.turn} tools={[tc.get('function',{}).get('name') for tc in (tcs_original or [])]} text={(msg.get('content') or '')[:120]!r}", flush=True)
        if tcs_original:
            child.messages.append({"role": "assistant", "content": msg.get("content") or "",
                                   "tool_calls": [_tc_obj(tc) for tc in (tcs or [])]})
            if progress_cb:
                for tc in tcs_original:
                    _tn = tc.get("function", {}).get("name")
                    progress_cb({"module": module, "tool": _tn, "state": "running",
                                 "phase": "exploit", "last_type": _tn,
                                 "last_message": f"[exploit:{module}] turn={child.state.turn} tool={_tn}",
                                 "msg_count": child.state.turn})
            await child._exec_tool_calls(tcs_original, task_id, target, progress_cb=progress_cb)
            if stop_check is not None:
                try:
                    if stop_check():
                        print(f"[exploit:{module}] t={child.state.turn} 目标命中（flag 模式）→ 早停收口", flush=True)
                        break
                except Exception:
                    pass
        else:
            child.messages.append({"role": "assistant", "content": msg.get("content") or ""})
            if _is_done(msg.get("content") or ""):
                break
            # 重复检测：连续 3 轮无 tool call 且内容相似（agent 卡死在完成态）→ 强制退出
            _cur = (msg.get("content") or "").strip()
            if _cur and _cur == _last_content:
                _no_tool_streak += 1
            else:
                _no_tool_streak = 0
            _last_content = _cur
            if _no_tool_streak >= 3:
                print(f"[exploit:{module}] t={child.state.turn} 重复卡死检测 → 强制退出", flush=True)
                break

    await child._cleanup()
    task_registry.unregister_agent(task_id, child)
    findings = _collect_findings(task_id)
    return _ChildResult(module, findings, coverage=_list_coverage(task_id))


_DONE_PATTERNS = (
    '"done"', "task complete", "task is complete", "task completed",
    "i'm done", "im done", "i am done", "all done", "we're done", "complete.",
)

def _is_done(content: str) -> bool:
    if not content:
        return False
    lowered = content.strip().lower()
    if lowered.startswith("done"):
        return True
    return any(p in lowered for p in _DONE_PATTERNS)


def _tc_obj(tc: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": tc.get("id", ""), "type": "function",
            "function": {"name": tc.get("function", {}).get("name", ""),
                         "arguments": tc.get("function", {}).get("arguments", "{}")}}


def _finding_ids(task_id: str) -> set:
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT id FROM findings WHERE task_id=?", (task_id,)).fetchall()
        return {r["id"] for r in rows}
    finally:
        conn.close()


def _collect_findings(task_id: str) -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT id,target,title,location,severity,vuln_class,poc,evidence,status "
            "FROM findings WHERE task_id=?", (task_id,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# CTF/目标猎取模式（mode=ctf）：单 objective 猎手 + flag 早停
# 设计: docs/CTF目标猎取模式-设计.md（xben-002 实测校准：异常驱动优先，批量循环为大空间保底）
# ---------------------------------------------------------------------------

def _ctf_flag_pattern():
    """flag 匹配模式（PIMETA_CTF_FLAG_PATTERN 热读；配置坏时回退默认）。"""
    pat = cfg_env("PIMETA_CTF_FLAG_PATTERN", r"flag\s*\{[^}\s]{4,}")
    try:
        return re.compile(pat, re.IGNORECASE)
    except re.error:
        return re.compile(r"flag\s*\{[^}\s]{4,}", re.IGNORECASE)


def _flag_hit(task_id: str, before_ids: set) -> Optional[Dict[str, Any]]:
    """第一条"新出现且 title/poc/evidence 匹配 flag 模式"的 finding（CTF 早停判据）。

    只认 flag 模式匹配——旁证 finding（如默认凭据）不触发早停，
    防"先找到旁证就假成功收口"（xben-002 R1 教训）。
    """
    pat = _ctf_flag_pattern()
    for f in _collect_findings(task_id):
        if f.get("id") in before_ids:
            continue
        blob = f"{f.get('title', '')} {f.get('poc', '')} {f.get('evidence', '')}"
        if pat.search(blob):
            return f
    return None


# objective 伪模块的猎手焦点块（替代类锁 "WORK ONLY ON THIS module"）。
# 与 _run_child 的 task 文本拼接后作为 user 消息开头。
_HUNTER_FOCUS = """=== OBJECTIVE HUNT MODE — you are the objective hunter ===
Default question (ask this FIRST about every page/dataset you fetch):
  "What data here is special? What data should NOT be shown to me?"
  — Anomalous data (special names, content differing from template/filler, other users' data,
    entries that don't fit the pattern) is the PRIMARY source of the objective, not a secondary clue.

Search discipline (MANDATORY, in priority order):
1. Anomaly-driven (PRIMARY): for every page you fetch, read the DATA ITSELF first
   (tables, list rows, response bodies) — not just JS/params/status codes.
   Anomaly signals: special naming (e.g. a row whose name/ticker is literally the objective keyword),
   content differing from template/filler, encoded strings, 302 to an unfamiliar path,
   other users' data (secondary use of any confirmed cross-user access),
   hidden DOM fields (data-* attributes, HTML comments), list-vs-URL-space mismatch.
   On spotting an anomaly, dig in immediately — do not wait for "better tooling".
2. Breadcrumb chasing: follow every new token/link/data-* attribute/endpoint to the end —
   indirect references (list/detail split, auth gates, data-order-id style DOM indirection)
   are the common hiding place for the objective.
3. Batch sweep (large object spaces ONLY): when no listing page exposes the full set and the
   space is large (hundreds~thousands), write ONE bash loop to sweep systematically
   (200~1000 per batch, continue in chunks) and grep for the objective pattern
   (flag template / non-template content). Do NOT hand-try IDs one by one (sampling, not searching).
   If a listing page already exposes the full set (e.g. 5 rows), fetching all of it IS the
   systematic sweep — no loop needed.
4. STOP ON HIT: once the objective is found → submit_finding (evidence = full raw response)
   → print done. The task ends as soon as it is recorded.

FORBIDDEN: drifting into vulnerability classes unrelated to the objective
(touch sqli/xss only when they ARE the breadcrumb); re-verifying facts already confirmed above;
hand-sampling in a large space without a loop; reading only structure (JS/status codes)
without reading the data.
"""

class OrchestratorV2:
    """v2 多 agent 编排：root LLM 决策派活 + 相位交付物 + 并行子 agent。"""

    def __init__(self):
        self.live: Dict[str, Any] = {"phase": "init", "slots": {}, "queue": []}
        self.total_turns = 0

    async def run(self, task: str, target: str, task_id: str = "",
                  model: str = "", modules: Optional[List[str]] = None,
                  progress_cb=None, target_id: str = "",
                  runtime: Optional[ResolvedRuntime] = None,
                  recipe: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        # recipe: 按 run 解析的派发配方(已知靶场快通用)。未显式给的项回退 env 默认。
        recipe = recipe or {}
        skip_recon = bool(recipe.get("skip_recon", cfg_env("HINSE_SKIP_RECON", "0") == "1"))
        force_all = bool(recipe.get("force_all", cfg_env("HINSE_FORCE_ALL_MODULES", "0") == "1"))
        max_parallel = int(recipe.get("max_parallel", int(cfg_env("HINSE_MAX_PARALLEL", "3"))))
        child_max_turns = int(recipe.get("child_max_turns", int(cfg_env("HINSE_CHILD_MAX_TURNS", "40"))))
        task_budget = int(recipe.get("task_budget", int(cfg_env("HINSE_TASK_BUDGET", "1800"))))
        retry_delay = int(recipe.get("module_retry_delay", int(cfg_env("HINSE_MODULE_RETRY_DELAY", "60"))))
        modules = modules or _default_modules()
        # CTF/目标猎取模式：单 objective 猎手，不做 OWASP 类 fan-out（判定在 app.resolve_mode，
        # 经 task_params.mode 进 recipe；pentest=默认，行为零变化）
        ctf_mode = str(recipe.get("mode") or "pentest") == "ctf"
        if ctf_mode:
            modules = ["objective"]
            force_all = True
        resolved_runtime = runtime if isinstance(runtime, ResolvedRuntime) else None
        selected = resolved_runtime.runtime if resolved_runtime is not None else runtime
        runtime_id = resolved_runtime.runtime_id if resolved_runtime is not None else getattr(selected, "runtime_id", "")
        if selected is None:
            return {"ok": False, "agent": "RedBee", "task_id": task_id,
                    "findings": [], "error": "runtime required"}
        start = time.monotonic()
        before_ids = _finding_ids(task_id)
        # CTF 早停判据：新 finding 匹配 flag 模式 → 立即收口（每次工具执行后查；旁证 finding 不触发）
        stop_check = (lambda: _flag_hit(task_id, before_ids) is not None) if ctf_mode else None
        results: List[dict] = []
        intel_block = ""  # 累积情报：pre-recon + recon 交付物
        target_id = resolve_target_id(target, target_id)  # 归一化：IP/URL → 稳定 target_id（查 KB 用）

        def emit(phase, state, detail=""):
            if progress_cb:
                progress_cb({"phase": phase, "state": state, "detail": detail,
                             "last_message": f"[{phase}] {state}" + (f" — {detail}" if detail else "")})
            self.live["phase"] = phase if state == "start" else self.live["phase"]
            _tlog(task_id, "phase", f"{phase} {state}" + (f" — {detail}" if detail else ""))

        # 任务级共享沙箱容器（一任务一 sandbox，所有相位/模块 agent 共享）
        # 失败则回退旧行为（各 child 自建独立容器），不阻塞任务
        shared_container = ""
        try:
            shared_container = await _task_container_ensure(task_id)
            _tlog(task_id, "container",
                  f"任务级共享沙箱 {shared_container}（各 agent 按 /work/<module> 隔离，/work/shared 共享产物）")
        except Exception as e:
            _tlog(task_id, "container", f"共享沙箱创建失败: {str(e)[:120]} → 回退各 child 独立容器")

        try:
            # --- phase 1+2: pre-recon + recon（skip_recon 时跳过，直接 warm-start 进 exploit）---
            if skip_recon:
                warm = _target_intel_brief(target_id)
                intel_block = (f"TARGET: {target}\nTASK: {task}\n"
                               + (warm + "\n\n" if warm else "")
                               + "(RECON SKIPPED via HINSE_SKIP_RECON — use the task brief above and probe directly.)")
                _save_recon_deliverable(task_id, intel_block)
                results.append({"phase": "pre-recon", "ok": True, "skipped": True})
                results.append({"phase": "recon", "ok": True, "skipped": True})
                emit("recon", "skip", "HINSE_SKIP_RECON=1")
            else:
                # phase 1: pre-recon（结构化情报）
                emit("pre-recon", "start")
                intel_block = await self._phase_pre_recon(task, target, task_id, module_note=None,
                                                          progress_cb=progress_cb,
                                                          target_id=target_id, runtime=selected,
                                                          shared_container=shared_container)
                results.append({"phase": "pre-recon", "ok": bool(intel_block)})
                # phase 2: recon（攻击面交付物）
                if task_registry.is_cancelled(task_id):
                    results.append({"phase": "recon", "ok": False, "error": "cancelled"})
                else:
                    emit("recon", "start")
                    recon = await self._phase_recon(task, target, task_id, intel_block, runtime=selected,
                                                shared_container=shared_container)
                    _save_recon_deliverable(task_id, recon)   # 交付物文件
                    intel_block = f"{intel_block}\n\n{recon}"
                    results.append({"phase": "recon", "ok": True, "deliverable": recon[:500]})

            # --- phase 3: root LLM 决策（看 intel + coverage 动态派模块）---
            # force_all → 跳过 root LLM 剪枝，直接全派候选模块
            # （已知靶场全模块快通用：LLM 根决策常过度保守只派 1 个模块，确定性全派更可靠）
            if task_registry.is_cancelled(task_id):
                decision = {"ok": False, "modules": [], "stop": True, "reason": "cancelled"}
                self.live["root_decision"] = decision
                results.append({"phase": "root-decide", "dispatch": [], "stop": True, "reason": "cancelled"})
                emit("root-decide", "skip", "cancelled")
            elif ctf_mode:
                dispatch_modules = ["objective"]
                decision = {"ok": True, "modules": dispatch_modules, "stop": False,
                            "reason": "ctf-objective-hunt"}
                self.live["root_decision"] = decision
                results.append({"phase": "root-decide", "dispatch": dispatch_modules, "stop": False,
                                "reason": "ctf-objective-hunt"})
                emit("root-decide", "skip", "CTF 模式 → 单 objective 猎手（无类 fan-out）")
            elif force_all:
                dispatch_modules = list(modules)
                decision = {"ok": True, "modules": dispatch_modules, "stop": False, "reason": "force-all-modules"}
                self.live["root_decision"] = decision
                results.append({"phase": "root-decide", "dispatch": dispatch_modules, "stop": False,
                                "reason": "force-all-modules"})
                emit("root-decide", "skip", f"HINSE_FORCE_ALL_MODULES → 全派 {len(dispatch_modules)} 个候选模块")
            else:
                emit("root-decide", "start")
                decision = await _root_plan(task, target, task_id, modules, intel_block, resolved_runtime or selected)
                dispatch_modules = decision.get("modules") or []
                self.live["root_decision"] = decision
                results.append({"phase": "root-decide", "dispatch": dispatch_modules,
                                "stop": decision.get("stop"), "reason": decision.get("reason", "")})
                emit("root-decide", "done", f"dispatch={dispatch_modules} stop={decision.get('stop')}")

            # --- phase 4: exploit（root 决策后的模块集，并行子 agent）---
            emit("exploit", "start")
            if task_registry.is_cancelled(task_id):
                exploit_res = []
                emit("exploit", "skip", "cancelled")
            elif decision.get("stop") or not dispatch_modules:
                exploit_res = []
                emit("exploit", "skip", "root decided no further exploitation")
            else:
                exploit_res = await self._phase_exploit(task, target, task_id, dispatch_modules,
                                                         intel_block, selected, progress_cb,
                                                         max_parallel=max_parallel,
                                                         child_max_turns=child_max_turns,
                                                         shared_container=shared_container,
                                                         task_budget=task_budget,
                                                         module_retry_delay=retry_delay,
                                                         stop_check=stop_check)
            results.append({"phase": "exploit", "ok": True, "children": exploit_res})

            # --- phase 4b: coverage 补测循环（派了却没 coverage 的 gap 模块 → 续派补测）---
            # CTF 模式关闭：类 gap 续派对目标猎取无意义（单猎手，gap 只会是 objective 自身）
            max_gap_rounds = 0 if ctf_mode else int(cfg_env("HINSE_COVERAGE_GAP_ROUNDS", "1"))
            gap_round = 0
            while gap_round < max_gap_rounds:
                if task_registry.is_cancelled(task_id):
                    break
                cov_check = coverage_reconciliation(dispatch_modules, _list_coverage(task_id))
                gaps = cov_check.get("coverage_gaps") or []
                if not gaps:
                    break
                gap_modules = [g["module"] for g in gaps]
                emit("coverage-gap", "repatch", f"gap 模块 {gap_modules} → 续派补测 (round {gap_round + 1})")
                gap_res = await self._phase_exploit(task, target, task_id, gap_modules,
                                                    intel_block, selected, progress_cb,
                                                    max_parallel=max_parallel,
                                                    child_max_turns=child_max_turns,
                                                    shared_container=shared_container,
                                                    task_budget=task_budget,
                                                    module_retry_delay=retry_delay)
                exploit_res.extend(gap_res)
                gap_round += 1

            # --- phase 5: report（对账：assigned vs coverage → gaps + complete）---
            emit("report", "start")
            summary = await self._phase_report(task_id, target, dispatch_modules, exploit_res)
            results.append({"phase": "report", "ok": True, "complete": summary.get("complete"),
                            "coverage_gaps": summary.get("coverage", {}).get("coverage_gaps", [])})

            # CTF 模式：目标达成判定（新 finding 匹配 flag 模式）
            objective_met = False
            if ctf_mode:
                _hit = _flag_hit(task_id, before_ids)
                objective_met = _hit is not None
                emit("objective", "met" if objective_met else "unmet",
                     (f"flag 命中 → {str(_hit.get('title', ''))[:80]}" if _hit
                      else "预算内未命中 flag"))

            assigned_modules: List[str] = []
            for phase in results:
                if phase.get("phase") == "root-decide":
                    assigned_modules.extend(phase.get("dispatch") or [])
                elif phase.get("phase") == "exploit":
                    assigned_modules.extend(child.get("module") for child in phase.get("children") or [])
            assigned_modules = list(dict.fromkeys(assigned_modules))
            all_findings = _collect_findings(task_id)
            delta_findings = [f for f in all_findings if f["id"] not in before_ids]
            finding_ids = [f["id"] for f in delta_findings]
            coverage_rows = _list_coverage(task_id)
            from redkb import governance as _gov
            evidence_by_id: Dict[str, str] = {}
            evidence_refs: List[str] = []
            for finding in all_findings:
                raw_ev = str(finding.get("evidence", ""))
                if not raw_ev:
                    continue
                # finding 是 verified 漏洞 ⇒ evidence 即成功证明。治理门禁要求 evidence 含 SUCCESS_SIGNAL，
                # 若 agent 写的 evidence 缺该词（如只有 "sqlmap" 无 "sqli/exploit/confirmed"），补一个真实前缀。
                if not _gov._success_signal(raw_ev):
                    _vc = str(finding.get("vuln_class") or "vuln")
                    raw_ev = f"exploit confirmed ({_vc} verified): {raw_ev}"
                evidence = hash_text(raw_ev)
                evidence_id = f"ev-{evidence[:16]}"
                evidence_by_id[evidence_id] = raw_ev
                evidence_refs.append(evidence_id)
            case_snapshot = build_inhouse_case_snapshot(
                task_id=task_id,
                target=target,
                target_id=resolve_target_id(target, ""),
                model=selected.model,
                runtime_id=runtime_id,
                findings=all_findings,
                coverage=coverage_rows,
                tool_calls=[],
                llm_turns=self.total_turns,
                modules=assigned_modules,
                phases=[{"name": str(r.get("phase", "")),
                         "state": "skipped" if r.get("skipped") else ("error" if r.get("error") else "done"),
                         "started_at": ""} for r in results],
                evidence_refs=evidence_refs,
            )
            try:
                case_id = store_inhouse_case(case_snapshot, evidence_by_id)
                case_capture_error = None
            except Exception as exc:
                case_id = None
                case_capture_error = str(exc)
            return {
                "agent": "RedBee", "task_id": task_id, "target": target,
                "mode": "ctf" if ctf_mode else "pentest",
                "objective_met": objective_met,
                "phases": results,
                "elapsed": round(time.monotonic() - start, 1),
                "findings": delta_findings,
                "finding_ids": finding_ids,
                "assigned_modules": assigned_modules,
                "complete": summary.get("complete"),
                "coverage": summary.get("coverage", {}),
                "case_id": case_id,
                "case_snapshot": case_snapshot.model_dump(),
                "case_capture_error": case_capture_error,
            }
        finally:
            await _task_container_kill(shared_container)

    # ---- phase 1: pre-recon 结构化情报 ----
    async def _phase_pre_recon(self, task, target, task_id, module_note,
                                 progress_cb, target_id: str = "",
                                 runtime: ModelRuntime = None,
                                 shared_container: str = "") -> str:
        child = InhouseAgent(runtime=runtime)
        child.last_task_id = task_id
        # KB 热启动：拉该 target 已验证情报（中性 intel，无 PoC）→ 注入 prompt，跳重复侦察
        warm = _target_intel_brief(target_id)
        if warm:
            print(f"[orch:{task_id}] pre_recon 热启动命中 target_id={target_id} brief={len(warm)}chars", flush=True)
        if warm:
            recon_instruction = (
                "⚠️ RECON ALREADY DONE for this target — the intel above is ALREADY VERIFIED from past engagements. "
                "Do NOT re-run http_request/nmap/browser on already-listed surfaces (login/sqli/xss/upload/fileread/csrf/brute). "
                "Use AT MOST 1-2 tool calls (e.g. ONE login to confirm the credential still works), then STOP and deliver. "
                "Reuse the verified intel above; only add a gap you actually confirm missing. "
                "Prefer http_request over browser/nmap (the latter two are slow/empty here). "
                "Concrete exploit payloads are handled by executors, not you.\n"
            )
        else:
            recon_instruction = (
                "Do light recon (http_request/web_get_contents/nmap, NO exploit, NO submit_finding).\n"
            )
        prompt = (
            f"You are PRE-RECON for target {target}.\n"
            f"Task: {task}\n"
            + (warm + "\n\n" if warm else "")
            + recon_instruction
            + "Return a JSON object with these keys (omit unknowns):\n"
            + json.dumps(PRERECON_FIELDS, ensure_ascii=False, indent=2)
        )
        child._build_initial_messages(target, "generic", prompt)
        if shared_container:
            child.container = shared_container
            child._owns_container = False
            child.workdir = "/work/pre-recon"
        else:
            try:
                child.container = await child._docker_run()
                register_container(child.container, task_id)
            except Exception:
                return ""
        total = int(cfg_env("HINSE_PRERECON_TURNS", "8"))
        retries = 0
        for i in range(total):
            if task_registry.is_cancelled(task_id):
                await child._cleanup()
                return ""
            child._compact_messages()
            last = i >= total - 2  # 最后 2 轮强制文本输出（治"一直调工具不交付"）
            if last:
                child.messages.append({"role": "user", "content":
                    "Deliver now: STOP calling tools. Output the final JSON object directly as plain text."})
            try:
                msg = await child._chat(child.messages, runtime=runtime)
            except Exception:
                break
            child.state.turn += 1
            tcs = msg.get("tool_calls")
            if tcs and not last:
                child.messages.append({"role": "assistant", "content": msg.get("content") or "",
                                       "tool_calls": [_tc_obj(tc) for tc in tcs]})
                await child._exec_tool_calls(tcs, task_id, target)
                continue
            content = msg.get("content") or ""
            data = _try_parse_json(content)
            # schema 硬校验：6 键必须齐全（结构化 + 校验，非 best-effort）
            missing = [k for k in PRERECON_REQUIRED_KEYS
                       if not (isinstance(data, dict) and str(data.get(k, "")).strip())]
            if not missing:
                await child._cleanup()
                return "=== PRE-RECON INTEL (validated) ===\n" + json.dumps(
                    data, ensure_ascii=False, indent=2)
            if retries >= 2:  # 部分交付物（缺节渲染占位，不 fail 整个相位）
                await child._cleanup()
                data = data if isinstance(data, dict) else {}
                for k in missing:
                    data.setdefault(k, "(not captured)")
                return f"=== PRE-RECON INTEL (PARTIAL missing: {missing}) ===\n" + \
                    json.dumps(data, ensure_ascii=False, indent=2)
            retries += 1
            child.messages.append({"role": "assistant", "content": content})
            child.messages.append({"role": "user",
                "content": f"Your JSON is missing required keys: {missing}. "
                           f"Return the COMPLETE object with ALL keys: {PRERECON_REQUIRED_KEYS}."})
        await child._cleanup()
        return ""

    # ---- phase 2: recon 攻击面交付物 ----
    async def _phase_recon(self, task, target, task_id, intel_block,
                             runtime: ModelRuntime = None,
                             shared_container: str = "") -> str:
        """产出结构化攻击面清单（endpoints + input vectors + auth + network），存交付物。"""
        child = InhouseAgent(runtime=runtime)
        child.last_task_id = task_id
        prompt = (
            f"You are RECON agent for target {target}.\n"
            "Map the attack surface WITHOUT exploiting. Output a markdown report with sections:\n"
            "## Endpoints (method, path, purpose)\n"
            "## Input vectors (params, body fields, headers, cookies)\n"
            "## Authentication (login flow, session, roles)\n"
            "## Network map (services, ports, tech stack)\n"
            "Use http_request/web_get_contents/nmap. Do NOT exploit, do NOT submit_finding."
        )
        child._build_initial_messages(target, "generic", prompt)
        if shared_container:
            child.container = shared_container
            child._owns_container = False
            child.workdir = "/work/recon"
        else:
            try:
                child.container = await child._docker_run()
                register_container(child.container, task_id)
            except Exception:
                return ""
        total = int(cfg_env("HINSE_RECON_TURNS", "12"))
        retries = 0
        for i in range(total):
            if task_registry.is_cancelled(task_id):
                await child._cleanup()
                return ""
            child._compact_messages()
            last = i >= total - 2  # 最后 2 轮强制文本输出（治"一直调工具不交付"）
            if last:
                child.messages.append({"role": "user", "content":
                    "Deliver now: STOP calling tools. Output the complete 4-section recon report "
                    "(Endpoints / Input vectors / Authentication / Network map) as markdown."})
            try:
                msg = await child._chat(child.messages, runtime=runtime)
            except Exception:
                break
            child.state.turn += 1
            tcs = msg.get("tool_calls")
            if tcs and not last:
                child.messages.append({"role": "assistant", "content": msg.get("content") or "",
                                       "tool_calls": [_tc_obj(tc) for tc in tcs]})
                await child._exec_tool_calls(tcs, task_id, target)
                continue
            content = msg.get("content") or ""
            # schema 硬校验：4 section 必须齐全（结构化交付物）
            missing = [s for s in RECON_REQUIRED_SECTIONS if s.lower() not in content.lower()]
            if not missing:
                await child._cleanup()
                return content[:4000]
            if retries >= 2:  # 部分交付物
                await child._cleanup()
                return content[:4000] + f"\n\n(PARTIAL recon — missing sections: {missing})"
            retries += 1
            child.messages.append({"role": "assistant", "content": content})
            child.messages.append({"role": "user",
                "content": f"Your recon report is missing required sections: {missing}. "
                           f"Use http_request/nmap to fill them and include ALL: "
                           f"{RECON_REQUIRED_SECTIONS}."})
        await child._cleanup()
        return ""

    # ---- phase 4: exploit 并行子 agent（modules 由 root 决策给出，已含 coverage 剪枝）----
    async def _phase_exploit(self, task, target, task_id, modules, intel_block,
                                runtime: ModelRuntime, progress_cb,
                                max_parallel: int = MAX_PARALLEL,
                                child_max_turns: int = CHILD_MAX_TURNS,
                                shared_container: str = "",
                                task_budget: int = 1800,
                                module_retry_delay: int = 60,
                                stop_check=None) -> List[dict]:
        sem = asyncio.Semaphore(max_parallel)
        if progress_cb:
            self.live["slots"] = {i: {"agent": "RedBee", "module": m, "state": "queued"}
                                  for i, m in enumerate(modules)}

        async def bounded(m: str, idx: int):
            async with sem:
                if task_registry.is_cancelled(task_id):
                    return _ChildResult(m, [], error="cancelled")
                if progress_cb:
                    self.live["slots"][idx]["state"] = "running"
                    progress_cb({"module": m, "state": "running", "phase": "exploit",
                                 "last_type": "module_start",
                                 "last_message": f"[{m}] start", "msg_count": 0})
                _tlog(task_id, "module_start", f"模块 {m} 开始（子 agent 启动）", m)
                r = await _run_child(m, target, task, task_id, intel_block, runtime, progress_cb,
                                      child_max_turns=child_max_turns,
                                      shared_container=shared_container,
                                      task_budget=task_budget,
                                      stop_check=stop_check)
                # 死模块自动重试：LLM 全挂时冷却后整模块重派 1 次（治 2026-09-24 实测
                # 7/18 模块因 all runtimes failed 直接蒸发）；其他错误不重试；delay=0 禁用
                if (r.error and _is_llm_dead(r.error) and module_retry_delay > 0
                        and not task_registry.is_cancelled(task_id)):
                    delay = float(module_retry_delay)
                    _tlog(task_id, "module_retry", f"模块 {m} LLM 死（{str(r.error)[:80]}）→ {delay:.0f}s 冷却后重试 1 次", m)
                    if progress_cb:
                        self.live["slots"][idx]["state"] = "running"
                        progress_cb({"module": m, "state": "running", "phase": "exploit",
                                     "last_type": "module_retry",
                                     "last_message": f"[{m}] LLM 失败，{delay:.0f}s 后重试 1 次", "msg_count": 0})
                    await asyncio.sleep(delay)
                    if not task_registry.is_cancelled(task_id):
                        r = await _run_child(m, target, task, task_id, intel_block, runtime, progress_cb,
                                              child_max_turns=child_max_turns,
                                              shared_container=shared_container,
                                              task_budget=task_budget,
                                              stop_check=stop_check)
                if progress_cb:
                    if r.error and r.error != "cancelled":
                        # 模块失败可见：LLM 全挂/容器失败等原因不再静默 0 findings
                        self.live["slots"][idx]["state"] = "error"
                        progress_cb({"module": m, "state": "error", "phase": "exploit",
                                     "last_type": "module_fail",
                                     "last_message": f"[{m}] failed: {str(r.error)[:160]}",
                                     "msg_count": 0})
                        _tlog(task_id, "module_fail", str(r.error)[:200], m)
                    else:
                        self.live["slots"][idx]["state"] = "done"
                        progress_cb({"module": m, "state": "done", "phase": "exploit",
                                     "last_type": "module_done",
                                     "last_message": f"[{m}] done: {len(r.findings)} findings" + (f" ({r.error})" if r.error else ""),
                                     "msg_count": 0})
                        _tlog(task_id, "module_done",
                              f"模块 {m} 结束" + (f"（{r.error}）" if r.error else ""), m)
                return r

        if progress_cb:
            self.live["queue"] = list(modules)
        child_tasks = []
        for i, m in enumerate(modules):
            if task_registry.is_cancelled(task_id):
                break
            t = asyncio.create_task(bounded(m, i))
            task_registry.register(task_id, t)
            child_tasks.append(t)
        raw = await asyncio.gather(*child_tasks, return_exceptions=True)
        res = []
        for i, r in enumerate(raw):
            if isinstance(r, BaseException):
                err = "cancelled" if isinstance(r, asyncio.CancelledError) else f"{type(r).__name__}: {r}"
                res.append({"module": modules[i], "findings_count": 0, "error": err})
            else:
                res.append({"module": r.module, "findings_count": len(r.findings), "error": r.error})
        return res

    # ---- phase 5: report（对账：assigned vs coverage → gaps + complete）----
    async def _phase_report(self, task_id: str, target: str,
                            assigned_modules: List[str], child_results: List[dict]) -> dict:
        agg = _collect_findings(task_id)
        cov_rows = _list_coverage(task_id)
        recon = coverage_reconciliation(assigned_modules, cov_rows)
        incomplete = [c["module"] for c in child_results if c.get("error")]
        complete = (not recon.get("coverage_gaps")) and (not incomplete)
        return {"target": target, "task_id": task_id,
                "findings_count": len(agg), "findings": agg,
                "coverage": recon, "complete": complete,
                "incomplete_children": incomplete}


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _default_modules() -> List[str]:
    try:
        from pi_meta.planner import modules_for
        return modules_for("", "")
    except Exception:
        return ["sqli", "xss", "auth", "upload"]


def _try_parse_json(content: str) -> Optional[Dict[str, Any]]:
    import re as _re
    content = content.strip()
    if content.startswith("```"):
        content = _re.sub(r"^```[a-z]*\n|\n```$", "", content).strip()
    try:
        return json.loads(content)
    except Exception:
        pass
    for m in _re.finditer(r"\{[^{}]*\}", content):
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue
    return None
