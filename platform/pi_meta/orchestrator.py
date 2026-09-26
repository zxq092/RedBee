"""编排循环: 并行 agent + 漏洞板实时协调。

    1. planner 拆攻击模块(固定 OWASP 清单, 受 PIMETA_MAX_MODULES 上限)
    2. 每个 agent 槽位领一个模块并行打(派发 prompt 带"已确认清单"→ 跳过)
    3. 回收: LLM 解析结构化 findings → 贴板
    4. 新 high/critical 发现 → 派【另一个】agent 复现 PoC(阈值=1)
    5. 复现通过 → confirmed(后续派发跳过); 失败 → false_positive
    6. 循环直到 模块打空 / 无可派验证 / 预算(PIMETA_TASK_BUDGET)耗尽

注意: 取消任务不会停掉引擎侧仍在执行的 flow(它自己会跑完), 只是不再等待。
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from collections import deque
from typing import Callable, Optional

from config import env as cfg_env

from . import board, planner, sessions
from .real_dispatch import (agent_key, build_exploit_prompt, build_verify_prompt,
                            extract_findings, parse_verify, run_slot)
from agents import task_registry

POLL_WAIT = 30.0  # asyncio.wait 最长等待, 用于周期性检查预算


def _budget_seconds() -> int:
    return int(cfg_env("PIMETA_TASK_BUDGET", "5400"))


def outer_slot_modules(target: str, task: str, target_id: str = "") -> list[str]:
    """外层槽位模块列表。

    v2（默认）：引擎内部已做全模块 fan-out（root-decide/force-all 全派候选模块），
    外层只需 1 个槽位。旧版外层 fan-out N 个模块槽位、每个槽位把全部 9 模块流水线
    重跑一遍 → N 倍冗余重跑（R10 实测 2 波×9=18 个子 agent 烧掉整轮预算）。
    v1（HINSE_V2=0 单 agent）：每槽位打一个模块，保留外层 fan-out。"""
    mods = planner.modules_for(target, task, target_id)
    if cfg_env("HINSE_V2", "1") not in ("", "0", "false", "False"):
        return mods[:1]
    return mods


async def orchestrate(task_id: str, agents: list[str], task: str, target: str,
                      on_event: Optional[Callable[[str, str], None]] = None,
                      on_progress: Optional[Callable[[dict], None]] = None,
                      target_id: str = "", session_id: str = "",
                      task_params: dict = None) -> list[dict]:
    """跑协调循环, 返回全部子任务结果(每个含 findings 字段, 供 report.aggregate)。

    on_progress(live)：槽位进度变化即回调(派发/轮询/完成), live 形如
      {"slots": {slot_id: {agent,kind,label,flow_id,flow_status,state,msg_count,last_message}},
       "queue": [...], "verify_q": [...]}
    """
    slots = [(i, a) for i, a in enumerate(agents or ["RedBee"])]
    from agents.tools import resolve_target_id
    normalized_target_id = resolve_target_id(target, target_id)
    mod_q: deque = deque(outer_slot_modules(target, task, normalized_target_id))
    planned_modules = list(mod_q)
    ver_q: deque = deque()            # 待确认 {fid, f, exclude_slot}(槽位级, 支持同名引擎多 flow)
    busy: dict[int, asyncio.Task] = {}
    meta: dict[asyncio.Task, tuple] = {}
    results: list[dict] = []
    deadline = time.monotonic() + _budget_seconds()
    live: dict = {"slots": {}, "queue": list(mod_q), "verify_q": []}
    from .model_router import ModelRouter
    # 每任务模型覆盖：指定模型排第一候选（trusted 内部调用），挂则自动降级回队列其余
    _explicit = (task_params or {}).get("model")
    _resolved = await ModelRouter().resolve_runtime(explicit=_explicit, trusted=True)
    if not _resolved.ok or _resolved.runtime is None:
        error = _resolved.error
        sessions.save_task_metadata(
            task_id, target, normalized_target_id, "", list(agents or ["RedBee"]),
            [m for m in planned_modules if m in planner.MODULES], "runtime_error",
            runtime_error_code=error.code if error else "CONFIG_ERROR",
            runtime_error_summary=error.redacted_message if error else "runtime resolution failed")
        raise RuntimeError(error.redacted_message if error else "runtime resolution failed")
    runtime = _resolved.runtime
    sessions.save_task_metadata(
        task_id, target, normalized_target_id, runtime.runtime.model, list(agents or ["RedBee"]),
        [m for m in planned_modules if m in planner.MODULES], "running",
        runtime_model=runtime.runtime.model, runtime_id=runtime.runtime_id,
        degraded_from=runtime.degraded_from or "", degraded_chain=json.dumps(runtime.degraded_chain),
        model_override="", session_id=session_id, task_text=task)

    def emit(kind: str, detail: str) -> None:
        if on_event:
            try:
                on_event(kind, detail)
            except Exception:
                pass

    def push() -> None:
        if not on_progress:
            return
        live["queue"] = list(mod_q)
        live["verify_q"] = [{"fid": v["fid"],
                             "title": str(v["f"].get("title", ""))[:60],
                             "exclude_slot": v["exclude_slot"]} for v in ver_q]
        try:
            on_progress(live)
        except Exception:
            pass

    def launch(slot_id: int, agent: str, kind: str, payload: dict) -> None:
        if kind == "verify":
            text = build_verify_prompt(target, payload["f"])
        else:
            text = build_exploit_prompt(target, task, payload["module"],
                                        board.confirmed_brief(task_id))
        label = payload.get("module") or str(payload.get("f", {}).get("title", ""))[:60]
        live["slots"][slot_id] = {
            "agent": agent, "kind": kind, "label": label, "state": "dispatching",
            "flow_id": None, "flow_status": None, "msg_count": 0,
            "last_type": None, "last_message": "", "phase": "init",
        }

        def slot_progress(u: dict) -> None:
            s = live["slots"].get(slot_id)
            if s is None:
                return
            if u.get("flow_id"):
                s["flow_id"] = u["flow_id"]
            s["state"] = "done" if u.get("done") else "running"
            if u.get("phase"):
                s["phase"] = u["phase"]
            if u.get("flow_status"):
                s["flow_status"] = u["flow_status"]
            if u.get("msg_count") is not None:
                s["msg_count"] = u["msg_count"]
            if "detail" in u:
                # 相位级事件（recon/exploit 切换等, 来自 v2 emit）：清掉上一轮工具状态,
                # 否则前端把相位事件误判成"又调了一次工具"（合并式更新会残留旧 tool/result）。
                s["tool"] = None
                s["last_type"] = "phase"
                s["result"] = None
            else:
                # 工具 / 模块级事件
                if u.get("tool"):
                    s["tool"] = u["tool"]
                if u.get("last_type"):
                    s["last_type"] = u["last_type"]
                if u.get("module"):
                    s["module"] = u["module"]
                if u.get("result") is not None:
                    s["result"] = u["result"]
            if u.get("last_message"):
                s["last_message"] = u["last_message"]
            push()

        t = asyncio.create_task(run_slot(agent, text, target, runtime, slot_progress, task_id, target_id,
                                         task_params=task_params))
        task_registry.register(task_id, t)
        busy[slot_id] = t
        meta[t] = (slot_id, agent, kind, payload)
        emit("dispatch", f"{agent} <- {kind} {label}")
        push()

    def take_compatible_verify(slot_id: int) -> Optional[dict]:
        for i, item in enumerate(ver_q):
            if item["exclude_slot"] != slot_id:
                del ver_q[i]
                return item
        return None

    def any_compatible() -> bool:
        for item in ver_q:
            for sid, _a in slots:
                if item["exclude_slot"] != sid:
                    return True
        return False

    def refill() -> None:
        if task_registry.is_cancelled(task_id):
            return
        for slot_id, agent in slots:
            if slot_id in busy:
                continue
            item = take_compatible_verify(slot_id)
            if item is not None:
                launch(slot_id, agent, "verify", item)
            elif mod_q:
                launch(slot_id, agent, "exploit", {"module": mod_q.popleft()})
            # 该槽位无兼容验证、也无模块 → 空着(其他槽位可能还在跑)

    # 首发: 每槽位一个模块
    for slot_id, agent in slots:
        if mod_q:
            launch(slot_id, agent, "exploit", {"module": mod_q.popleft()})

    while True:
        if task_registry.is_cancelled(task_id):
            emit("cancelled", "任务被停止, 取消剩余子任务")
            for t in list(busy.values()):
                t.cancel()
            await asyncio.gather(*busy.values(), return_exceptions=True)
            busy.clear()
            break
        if not busy and not mod_q and (not ver_q or not any_compatible()):
            if ver_q:
                emit("skip_verify",
                     f"{len(ver_q)} 条发现无法确认(无发现者以外的可用 agent), 保持 found 状态")
            break
        if time.monotonic() >= deadline:
            emit("budget", "任务预算耗尽, 取消剩余子任务")
            for t in list(busy.values()):
                t.cancel()
            await asyncio.gather(*busy.values(), return_exceptions=True)
            break
        if not busy:
            refill()
            if not busy:
                break
        done, _ = await asyncio.wait(set(busy.values()), timeout=POLL_WAIT,
                                     return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            slot_id, agent, kind, payload = meta.pop(t)
            del busy[slot_id]
            try:
                res = t.result()
            except asyncio.CancelledError:
                continue
            except Exception as e:
                res = {"agent": agent, "error": str(e), "raw": "", "ok": False}
            if "findings" not in res:
                res["findings"] = []

            if kind == "exploit":
                fs = res.get("findings") or []
                if not fs and not res.get("ok"):
                    sessions.save_task_metadata(
                        task_id, target, normalized_target_id, runtime.runtime.model,
                        list(agents or ["RedBee"]), [m for m in planned_modules if m in planner.MODULES], status="runtime_error",
                        runtime_error_code=str(res.get("error", "")),
                        runtime_error_summary=str(res.get("error", ""))[:500])
                    raise RuntimeError(str(res.get("error", "agent execution failed")))
                if not fs:
                    extraction = await extract_findings(agent, res.get("raw", ""), runtime)
                    if not extraction.get("ok"):
                        sessions.save_task_metadata(
                            task_id, target, normalized_target_id, runtime.runtime.model,
                            list(agents or ["RedBee"]), [m for m in planned_modules if m in planner.MODULES], status="extraction_error",
                            runtime_error_code=(extraction.get("error").code if extraction.get("error") else "PARSE_ERROR"),
                            runtime_error_summary=(extraction.get("error").redacted_message if extraction.get("error") else "findings parse failed"))
                        raise RuntimeError(extraction.get("error").redacted_message if extraction.get("error") else "findings parse failed")
                    fs = extraction.get("findings") or []
                    for f in fs:
                        f.setdefault("evidence", "")
                    res["findings"] = fs
                new_ids = []
                for f in fs:
                    fid = f.get("id")
                    if fid is not None:
                        try:
                            fid = int(fid)
                        except (TypeError, ValueError):
                            fid = None
                    if fid is None:
                        fid = board.post(task_id, target, f, agent)
                    else:
                        row = board.get_finding(task_id, fid)
                        if row is None:
                            fid = board.post(task_id, target, f, agent)
                        else:
                            row = dict(row)
                    if fid is not None:
                        new_ids.append(fid)
                        emit("found", f"{agent} 发现 [{f.get('severity')}] {f.get('title')}")
                for fid in new_ids:
                    row = board.get_finding(task_id, fid)
                    if row and board.SEV_ORDER.get(str(row["severity"]).lower(), 0) >= board.SEV_ORDER["high"]:
                        ver_q.append({"fid": fid, "f": row, "exclude_slot": slot_id})
                        emit("verify_queued", f"待确认: {row['title'][:60]}")
            else:  # verify
                ok, _ev = parse_verify(res.get("raw", ""))
                if ok:
                    board.mark(task_id, payload["fid"], "confirmed", agent)
                    emit("confirmed", f"{agent} 复现确认: {payload['f'].get('title')}")
                else:
                    board.mark(task_id, payload["fid"], "false_positive", agent)
                    emit("refuted",
                         f"{agent} 复现失败(标记 false_positive): {payload['f'].get('title')}")
            results.append(res)
        refill()

    actual_modules: list[str] = []
    for result in results:
        actual_modules.extend(result.get("assigned_modules") or result.get("modules") or [])
    if not actual_modules:
        actual_modules = [m for m in planned_modules if m in planner.MODULES]
    actual_modules = list(dict.fromkeys(actual_modules))
    sessions.save_task_metadata(
        task_id, target, normalized_target_id, runtime.runtime.model, list(agents or ["RedBee"]),
        actual_modules, "done", runtime_model=runtime.runtime.model,
        runtime_id=runtime.runtime_id, degraded_from=runtime.degraded_from or "",
        degraded_chain=json.dumps(runtime.degraded_chain), model_override="", session_id=session_id)
    return results
