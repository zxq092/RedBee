"""真实分发: pi_meta 网关 → 自研 RedBee agent.

编排层单一引擎：RedBee Agent。
用法:
  - run_slot(...): 供 orchestrator 用, 跑一个限定子任务并返回 raw 输出
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
import uuid


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from config import REDKB_URL, env as cfg_env
from pi_meta.model_runtime import (
    DispatchResult,
    ExtractionResult,
    ModelRuntimeError,
    ResolvedRuntime,
    RuntimeClient,
)
from . import planner


# ---------- prompt 构造 ----------

def build_exploit_prompt(target: str, task: str, module: str,
                         skip_brief: str = "") -> str:
    """限定攻击模块的派发 prompt(带"已确认清单"让 agent 跳过 + KB 运行时直查指引)。

    module="objective"（CTF/目标猎取模式）：不做类锁定，数据面优先——
    侦察/猎手各相位都读这段文本，类焦点会把侦察带偏（实测 xben-003 被锁 sqli）。"""
    if module == "objective":
        parts = [f"CTF objective hunt on {target}. {task}",
                 "OBJECTIVE: a single target object (flag / shell / specific record) is hidden "
                 "somewhere in this target. The objective is usually hidden as ANOMALOUS DATA, "
                 "not as a vulnerability class — read the DATA (tables, list rows, response "
                 "bodies, IDs, special names) before the structure (JS, params, status codes)."]
        if skip_brief:
            parts.append(skip_brief)
        parts.append(
            "\nWork toward the OBJECTIVE, not a vulnerability class. Enumerate data surfaces "
            "(lists, tables, ID-bearing values) and chase every anomaly to its end. "
            "When the objective is in hand: submit_finding with the full raw response as "
            "evidence, then finish immediately — do not keep hunting."
        )
        return "\n".join(parts)
    desc = planner.MODULES.get(module, module)
    parts = [f"Pentest {target}. {task}", f"FOCUS AREA: {module} — {desc}."]
    if skip_brief:
        parts.append(skip_brief)
    parts.append(
        "\nWork ONLY within this focus area. For each vulnerability you find, live-verify it "
        "with a working PoC and capture concrete evidence (response snippet / leaked data).\n"
        "Finish with a concise report listing each verified vuln: "
        "title / endpoint / severity / PoC / evidence. "
        "If the area yields nothing after reasonable attempts, say so explicitly."
    )
    parts.append(
        "\nPRIOR ATTACK KNOWLEDGE (use it, do not rediscover): the orchestrator has injected a "
        "neutral, sanitized RED-KB intel block. Apply the listed techniques with deterministic "
        "validation tools; do not execute query commands or embed payloads in prose."
    )
    return "\n".join(parts)


def build_verify_prompt(target: str, f: dict) -> str:
    """独立验证 prompt: 让另一个 agent 重跑 PoC, 结尾必须给判定行。"""
    return (
        f"You are an independent VERIFICATION agent for target {target}.\n"
        f"Another agent claims this vulnerability:\n"
        f"  Title: {f.get('title')}\n"
        f"  Location: {f.get('location') or '(unknown)'}\n"
        f"  Claimed PoC: {f.get('poc') or '(derive from location)'}\n"
        f"  Claimed evidence: {str(f.get('evidence', ''))[:500]}\n\n"
        "Independently re-run the PoC (or an equivalent exploit). Do NOT trust the claim — "
        "reproduce it yourself with your own commands and capture fresh evidence.\n"
        "At the VERY END of your output, print EXACTLY one line:\n"
        "  VERIFY_RESULT: CONFIRMED   (if you reproduced it)\n"
        "  VERIFY_RESULT: REFUTED     (if you could not; explain why after that line)"
    )


# ---------- RedBee executor ----------

# 每任务参数覆盖（POST /api/task 的 params 字段）：覆盖全局 .env / 快通配方，只作用于本任务。
# 规格：名称 → (类型, 下限, 上限)
TASK_PARAM_SPECS = {
    "max_parallel": ("int", 1, 8),
    "max_modules": ("int", 1, 9),
    "child_max_turns": ("int", 5, 200),
    "task_budget": ("int", 300, 21600),
    "module_retry_delay": ("int", 0, 600),
    "skip_recon": ("bool", None, None),
    "force_all_modules": ("bool", None, None),
    "model": ("str", None, None),  # 本任务专用模型（排第一候选，挂则降级回队列）
    "modules": ("modules", None, None),  # 显式模块列表（逗号分隔，覆盖 planner 选取）
    "mode": ("mode", None, None),  # 任务模式：ctf(目标猎取) | pentest(默认，OWASP 类 fan-out)
}


def validate_task_params(raw) -> tuple[dict, list[str]]:
    """校验每任务参数覆盖。返回 (合法参数 dict, 错误列表)；未知键/越界/格式错被剔除并记错。"""
    out: dict = {}
    errs: list[str] = []
    if raw is None:
        return out, errs
    if not isinstance(raw, dict):
        return out, ["params 必须是对象"]
    for k, v in raw.items():
        spec = TASK_PARAM_SPECS.get(k)
        if spec is None:
            errs.append(f"未知参数 {k}")
            continue
        kind, lo, hi = spec
        try:
            if kind == "bool":
                out[k] = str(v).lower() in ("1", "true", "yes", "on")
            elif kind == "str":
                if not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", v):
                    errs.append(f"{k} 格式错误")
                    continue
                if k == "model":
                    from config import model_priority
                    try:
                        queue = model_priority()
                    except Exception:
                        queue = []
                    if queue and v not in queue:
                        errs.append(f"model 不在已配置队列（可用: {'/'.join(queue)}）")
                        continue
                out[k] = v
            elif kind == "mode":
                mv = str(v).strip().lower()
                if mv not in ("ctf", "pentest"):
                    errs.append(f"{k} 必须是 ctf 或 pentest（收到: {v!r}）")
                    continue
                out[k] = mv
            elif kind == "modules":
                if not isinstance(v, str):
                    errs.append(f"{k} 必须是字符串（逗号分隔模块名）")
                    continue
                from .planner import MODULES as _MODS
                names = [x.strip() for x in v.split(",") if x.strip()]
                bad = [x for x in names if x not in _MODS]
                if not names or bad:
                    errs.append(f"{k} 无效（合法模块: {'/'.join(_MODS)}；未知: {','.join(bad) or '(空)'}）")
                    continue
                out[k] = names
            else:
                iv = int(v)
                if (lo is not None and iv < lo) or (hi is not None and iv > hi):
                    errs.append(f"{k} 超出范围 {lo}-{hi}")
                    continue
                out[k] = iv
        except (TypeError, ValueError):
            errs.append(f"{k} 格式错误")
    return out, errs


def merge_task_params(recipe: dict, task_params: dict) -> dict:
    """每任务参数覆盖合并进快通配方（任务级 > 配方级 > .env 默认）。
    force_all_modules → 配方键 force_all；task_budget/module_retry_delay 原样进配方由编排层消费。"""
    merged = dict(recipe)
    for k, v in (task_params or {}).items():
        merged["force_all" if k == "force_all_modules" else k] = v
    return merged


async def _inhouse_run(text: str, target: str, runtime: ResolvedRuntime,
                        task_id: str = "", progress_cb=None, target_id: str = "",
                        task_params: dict = None) -> DispatchResult:
    """自研执行器：KB-first + PoC 门禁 + 硬预算 + 端点 fail-fast。

    HINSE_V2=1（默认）→ 走 v2 多 agent 编排（root+相位+并行子 agent）
    HINSE_V2=0 → 回退单 agent ReAct（v1）。
    调用时热读 .env，改 HINSE_V2 不用重启。
    task_params：每任务参数覆盖（并发/预算/轮次/侦察开关），只影响本任务。
    """
    if cfg_env("HINSE_V2", "1") not in ("", "0", "false", "False"):
        from agents.orchestrator_v2 import OrchestratorV2
        from pi_meta import target_profile
        # 已知靶场(有档案) → 自动套快通配方(跳侦察/全派/防过度验证)，免每次手动 env
        recipe = target_profile.resolve_recipe(target_id)
        is_known = bool(recipe)
        if task_params:
            recipe = merge_task_params(recipe, task_params)
        explicit_modules = (task_params or {}).get("modules")
        if explicit_modules:
            modules = explicit_modules
        else:
            modules = planner.modules_for(target, text, target_id,
                                          max_modules=recipe.get("max_modules"))
        if is_known:
            text = (text + "\n\n" + target_profile.known_task_suffix()).strip()
        orch = OrchestratorV2()
        result = await orch.run(text, target, task_id=task_id, runtime=runtime,
                                modules=modules, progress_cb=progress_cb,
                                target_id=target_id, recipe=recipe)
        assigned_modules = result.get("assigned_modules") or modules
        return DispatchResult(
            ok=bool(result.get("ok", True)),
            agent="RedBee",
            raw="",
            case_snapshot=result.get("case_snapshot"),
            findings=result.get("findings", []),
            runtime_id=runtime.runtime_id,
            error=result.get("error"),
        )
    from agents.executor import InhouseAgent
    agent = InhouseAgent(runtime=runtime)
    if task_params and task_params.get("task_budget"):
        agent.TASK_BUDGET = int(task_params["task_budget"])
    result = await agent.run(text, target, runtime=runtime, task_id=task_id)
    return DispatchResult(
        ok=bool(result.get("ok", True)),
        agent="RedBee",
        raw="",
        case_snapshot=result.get("case_snapshot"),
        findings=result.get("findings", []),
        runtime_id=runtime.runtime_id,
        error=result.get("error"),
    )


_ENGINE_RUNNERS = {"RedBee": _inhouse_run}

# 遗留兼容：把旧 agent 名归一/映射到 RedBee，避免历史请求报 unsupported
_AGENT_ALIAS = {"pentestAG": "RedBee"}


def agent_key(name: str) -> str:
    return _AGENT_ALIAS.get(name, name)


async def run_slot(agent_name: str, text: str, target: str, runtime: ResolvedRuntime,
                    progress_cb=None, task_id: str = "", target_id: str = "",
                    task_params: dict = None) -> dict:
    """跑一个子任务(自研 RedBee), 返回 {agent, raw, ...}; 异常不抛出(记进 error)。

    model：PI(ModelRouter) 解析出的模型。
    task_id：用于记账/关联。
    """
    key = agent_key(agent_name)
    fn = _ENGINE_RUNNERS.get(key)
    if fn is None:
        return {"agent": agent_name, "error": "unsupported", "raw": ""}
    try:
        result = await fn(text, target, runtime, task_id, progress_cb=progress_cb,
                          target_id=target_id, task_params=task_params)
        if hasattr(result, '__dataclass_fields__'):
            d = dict(vars(result))
            if d.get("error") is not None:
                d["error"] = d["error"].redacted_message if hasattr(d["error"], "redacted_message") else str(d["error"])
            return d
        return result
    except Exception as e:
        return {"agent": agent_name, "error": str(e), "raw": ""}


# ---------- 结果解析 ----------

FINDINGS_SYSTEM = (
    "Extract the vulnerabilities that were ACTUALLY found and LIVE-VERIFIED (working PoC + "
    "evidence) from the following pentest agent output. Ignore theoretical or untested items.\n"
    "Output ONLY a JSON array (no markdown fences, no commentary); each element:\n"
    '{"title": "...", "asset": "endpoint/parameter", '
    '"severity": "critical|high|medium|low|info", '
    '"poc": "the working command/URL/request", '
    '"evidence": "response snippet / leaked data proving it", '
    '"vuln_class": "sqli|xss|auth|upload|cmdi|ssrf|idor|csrf|misconfig|other"}\n'
    "If no verified vulnerability exists, output: []"
)


def _error(code: str, stage: str, model: str, message: str) -> ModelRuntimeError:
    return ModelRuntimeError(code=code, stage=stage, model=model, redacted_message=message)


async def extract_findings(agent: str, raw: str, runtime: ResolvedRuntime) -> dict:
    """LLM 把 agent raw 输出解析成结构化 findings。失败返回 []。"""
    if not raw or not raw.strip():
        return {"ok": True, "findings": [], "runtime_id": runtime.runtime_id, "error": None}
    from llm_expert_extractor import _extract_json_list
    result = await RuntimeClient.chat(runtime.runtime, {
        "model": runtime.runtime.model,
        "messages": [
            {"role": "system", "content": FINDINGS_SYSTEM},
            {"role": "user", "content": raw[:26000]},
        ],
        "max_tokens": 6000,
        "temperature": 0.1,
    })
    if not result.ok or result.error:
        return {"ok": False, "findings": [], "runtime_id": runtime.runtime_id,
                "error": result.error}
    data = _extract_json_list(result.content)
    if not isinstance(data, list):
        return {"ok": False, "findings": [], "runtime_id": runtime.runtime_id,
                "error": _error("PARSE_ERROR", "parse", runtime.runtime.model, "invalid findings response")}
    out = []
    for f in data:
        if not isinstance(f, dict) or not str(f.get("title", "")).strip():
            continue
        f.setdefault("severity", "medium")
        f.setdefault("asset", "")
        out.append(f)
    return {"ok": True, "findings": out, "runtime_id": runtime.runtime_id, "error": None}


_VERIFY_RE = re.compile(r"VERIFY_RESULT:\s*(CONFIRMED|REFUTED)", re.I)


def parse_verify(raw: str) -> tuple[bool, str]:
    """取最后一处判定: (是否确认, 判定行之后的证据片段)。"""
    matches = list(_VERIFY_RE.finditer(raw or ""))
    if not matches:
        return False, ""
    last = matches[-1]
    tail = raw[last.end():last.end() + 600].strip()
    return last.group(1).upper() == "CONFIRMED", tail
