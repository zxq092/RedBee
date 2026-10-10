"""⑤ /btw 旁路提问（借 ARTEX /btw：不可变上下文快照 + 单次无工具 LLM 补全）。

语义：任务运行中，用户可"顺口问 agent 一句"而不打断主循环：
- 对某个运行中 agent 的 messages 取**深快照**（JSON 往返：主循环继续原地
  改原对象，不影响本次回答；也不向原 messages 追加任何内容）
- 追加一条 user 提问 + 旁路规则（直接回答、禁止工具、不继续主任务）
- **不带 tools** 调 LLM（纯文本补全）→ 答案原样返回
- 不写 agent 的 messages/state/pending_notes——主循环完全无感知（ARTEX 铁律：
  旁路提问不打断主循环、不能执行工具）

选 agent：
- 指定 module → 该模块专员；没有则回落到上下文最大者（响应里标注实际选谁）
- 不指定 → 上下文最大的运行中 agent（信息最全）

配置（.env 热加载）：
  BTW_TIMEOUT   单次补全超时（秒），默认 120
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict, List, Optional

import config
from .model_runtime import ResolvedRuntime, RuntimeClient, resolve_runtime

_BTW_RULES = (
    "[SIDE QUESTION /btw] The user is asking you a question WHILE the task is running:\n\n"
    "{question}\n\n"
    "Rules:\n"
    "- Answer directly from your current work context (what you have seen, tried, found so far).\n"
    "- Text only: do NOT call any tools and do NOT continue or resume the main task.\n"
    "- This question does not change your assigned task; after answering, you keep working as before.\n"
    "- Keep the answer concise (a few sentences or a short list)."
)


def snapshot_messages(messages: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """深快照（JSON 往返）：主循环后续对原列表/原 dict 的修改不影响快照。"""
    msgs = messages or []
    try:
        return json.loads(json.dumps(msgs, ensure_ascii=False))
    except (TypeError, ValueError):
        # 极端情况（不可序列化内容）：退化为逐条浅拷贝，content 尽量保型
        out: List[Dict[str, Any]] = []
        for m in msgs:
            if not isinstance(m, dict):
                continue
            c = dict(m)
            content = c.get("content")
            if content is not None and not isinstance(content, (str, int, float, bool)):
                try:
                    c["content"] = json.loads(json.dumps(content, ensure_ascii=False))
                except (TypeError, ValueError):
                    c["content"] = str(content)
            out.append(c)
        return out


def _ctx_chars(messages: List[Dict[str, Any]]) -> int:
    return sum(len(str(m.get("content") or "")) + sum(len(str(tc)) for tc in (m.get("tool_calls") or []))
               for m in messages)


def build_btw_payload(snapshot: List[Dict[str, Any]], question: str) -> Dict[str, Any]:
    """快照 + 旁路提问。注意：**不含 tools 键**——纯文本补全，模型无法执行工具。"""
    return {
        "messages": snapshot + [
            {"role": "user", "content": _BTW_RULES.format(question=question)},
        ],
        "max_tokens": 1024,
        "temperature": 0.2,
        "stream": False,
    }


def _most_informed(agents: List[Any]) -> Any:
    return max(agents, key=lambda a: _ctx_chars(getattr(a, "messages", None) or []))


def pick_agent(agents: List[Any], module: Optional[str] = None) -> Optional[Any]:
    """指定 module → 该模块专员；未命中/未指定 → 上下文最大者。"""
    if not agents:
        return None
    if module:
        matches = [a for a in agents if getattr(a, "_current_module", None) == module]
        if matches:
            return _most_informed(matches)
    return _most_informed(agents)


def _agent_info(agent: Any, snapshot: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "uid": getattr(agent, "_uid", ""),
        "module": getattr(agent, "_current_module", None),
        "turn": getattr(getattr(agent, "state", None), "turn", 0),
        "tool_calls": getattr(getattr(agent, "state", None), "tool_calls", 0),
        "n_messages": len(snapshot),
        "ctx_chars": _ctx_chars(snapshot),
    }


async def answer(task_id: str, question: str, module: Optional[str] = None) -> Dict[str, Any]:
    """对运行中任务旁路提问。绝不抛异常（端点故障不得影响主链路）。"""
    from agents import task_registry

    question = (question or "").strip()
    if not question:
        return {"ok": False, "error": "question required"}
    agents = task_registry.active_agents(task_id)
    if not agents:
        return {"ok": False, "error": "no active agent for this task"}
    agent = pick_agent(agents, module)
    snapshot = snapshot_messages(getattr(agent, "messages", None) or [])
    if not snapshot:
        return {"ok": False, "error": "agent context is empty (agent just started)"}
    selected: Optional[ResolvedRuntime] = getattr(agent, "runtime", None)
    if selected is None:
        resolution = await resolve_runtime()
        if not resolution.ok or resolution.runtime is None:
            return {"ok": False, "error": "no available runtime"}
        selected = resolution.runtime
    payload = build_btw_payload(snapshot, question)
    try:
        timeout = max(1.0, float(config.env("BTW_TIMEOUT", "120")))
    except (TypeError, ValueError):
        timeout = 120.0
    _t0 = time.monotonic()
    try:
        result = await asyncio.wait_for(RuntimeClient.chat(selected, payload), timeout)
    except asyncio.TimeoutError:
        return {"ok": False, "error": f"btw completion timed out after {timeout:.0f}s",
                "agent": _agent_info(agent, snapshot)}
    except Exception as exc:  # noqa: BLE001 —— 旁路故障隔离
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "agent": _agent_info(agent, snapshot)}
    _el = time.monotonic() - _t0
    print(f"[btw] task={task_id} module={getattr(agent, '_current_module', '') or '-'} "
          f"q={question[:60]!r} el={_el:.1f}s ok={result.ok}", flush=True)
    if not result.ok:
        return {"ok": False,
                "error": result.error.redacted_message if result.error else "model runtime failed",
                "agent": _agent_info(agent, snapshot)}
    return {"ok": True, "answer": result.content, "model": selected.runtime.model,
            "agent": _agent_info(agent, snapshot)}


__all__ = ["answer", "build_btw_payload", "pick_agent", "snapshot_messages"]
