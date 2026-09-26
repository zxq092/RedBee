"""任务级取消：登记一个 task 名下所有 asyncio 任务（bg/slot/child），统一 cancel + 物理杀沙箱容器。

为什么需要：asyncio task.cancel() 只终止等待链；真正的攻击载体是 Kali 沙箱容器
（inhouse-sess-XX，攻击命令在里面跑）+ 宿主机 docker exec 客户端。
stop = 标记 cancelled + cancel 所有登记任务 + docker rm -f 该 task 名下全部沙箱。
"""
from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional, Set

_CANCELLED: Set[str] = set()
_TASK_TASKS: Dict[str, Set["asyncio.Task"]] = {}
# 飞行中指令（in-run steer）：task_id -> 运行中 agent 集合（steer 日志见下方 steer 区）
_ACTIVE_AGENTS: Dict[str, set] = {}


def is_cancelled(task_id: str) -> bool:
    return bool(task_id) and task_id in _CANCELLED


def register(task_id: str, task: Optional["asyncio.Task"]) -> None:
    """登记 task 名下的 asyncio 任务；任务结束自动移除。"""
    if not task_id or task is None:
        return
    s = _TASK_TASKS.setdefault(task_id, set())
    s.add(task)

    def _drop(_t: "asyncio.Task", tid: str = task_id) -> None:
        ss = _TASK_TASKS.get(tid)
        if ss:
            ss.discard(_t)
        if not ss:
            _TASK_TASKS.pop(tid, None)

    task.add_done_callback(_drop)


def mark_cancelled(task_id: str) -> None:
    _CANCELLED.add(task_id)


def cancel_tasks(task_id: str) -> int:
    n = 0
    for t in list(_TASK_TASKS.get(task_id, ())):
        if not t.done():
            t.cancel()
            n += 1
    return n


async def kill_containers(task_id: str) -> int:
    """物理杀该 task 名下全部沙箱容器（docker rm -f），返回数量。"""
    from agents import executor
    return await executor.kill_containers_for_task(task_id)


async def cancel_task(task_id: str) -> dict:
    """一键停止：标记 + cancel 所有登记任务 + 物理杀沙箱。"""
    mark_cancelled(task_id)
    n = cancel_tasks(task_id)
    k = 0
    try:
        k = await kill_containers(task_id)
    except Exception as e:
        print(f"[cancel] kill_containers error: {type(e).__name__}: {e}", flush=True)
    return {"cancelled": n, "containers_killed": k}


# ---------------------------------------------------------------------------
# 飞行中指令（in-run steer）：运行中 agent 注册 + 指令注入
#
# 设计（2026-09-26）：指令不再是一次性队列（旧实现"第一个新 agent 吃掉、
# 整批其余拿不到"），而是**任务级 steer 日志**（带作用域标签，保留最近
# _STEER_LOG_CAP 条，任务结束清空）：
#   scope="all"      全局指令 → 所有 agent（含 recon 等任务级 agent）
#   scope=[modules]  定向指令 → 仅指定模块的专员 agent
# 新 agent 诞生（register_agent）时继承：全部 all 指令 + 指向自己模块的指令
#   → 相位间隙整批新 agent 全覆盖，且后起 agent 继承中途用户意图（如补的情报）
# ---------------------------------------------------------------------------

_AGENT_MODULE: Dict[int, Optional[str]] = {}   # id(agent) -> 模块名（None=任务级 agent）
_STEER_LOG: Dict[str, List[dict]] = {}         # task_id -> [{text, scope, ts}]
_STEER_LOG_CAP = 10


def _scope_matches(scope, module: Optional[str]) -> bool:
    """scope='all' → 所有人；scope=[modules] → 仅对应模块（任务级 agent 不收定向）。"""
    if scope == "all":
        return True
    return bool(module) and module in (scope or [])


def register_agent(task_id: str, agent, module: Optional[str] = None) -> None:
    """登记一个运行中的 agent 实例（InhouseAgent），并让它继承 steer 日志里
    相关的既有指令（all + 指向本模块的），治"整批新 agent 只有第一个吃到指令"。"""
    if not task_id or agent is None:
        return
    _ACTIVE_AGENTS.setdefault(task_id, set()).add(agent)
    _AGENT_MODULE[id(agent)] = module
    for entry in _STEER_LOG.get(task_id, ()):
        if _scope_matches(entry.get("scope"), module):
            try:
                agent.inject_note(entry.get("text", ""))
            except Exception:
                pass


def unregister_agent(task_id: str, agent) -> None:
    if not task_id or agent is None:
        return
    s = _ACTIVE_AGENTS.get(task_id)
    if s:
        s.discard(agent)
        if not s:
            _ACTIVE_AGENTS.pop(task_id, None)
    _AGENT_MODULE.pop(id(agent), None)


def active_agents(task_id: str) -> list:
    return list(_ACTIVE_AGENTS.get(task_id, ()))


def add_note(task_id: str, text: str, modules: Optional[List[str]] = None) -> int:
    """注入一条飞行中指令。

    modules=None → scope='all'（全局，所有运行中 agent 收）；
    modules=[...] → 仅指定模块的专员收（其他模块不被打扰）。
    指令同时记入任务级 steer 日志（cap _STEER_LOG_CAP），后续诞生的 agent
    注册时按作用域继承。返回立即注入的 agent 数（相位间隙=0，不丢）。
    """
    text = (text or "").strip()
    if not task_id or not text:
        return 0
    scope = "all" if not modules else [str(m).strip() for m in modules if str(m).strip()] or "all"
    log = _STEER_LOG.setdefault(task_id, [])
    log.append({"text": text, "scope": scope, "ts": time.time()})
    if len(log) > _STEER_LOG_CAP:
        del log[:len(log) - _STEER_LOG_CAP]
    n = 0
    for a in list(_ACTIVE_AGENTS.get(task_id, ())):
        if _scope_matches(scope, _AGENT_MODULE.get(id(a))):
            try:
                a.inject_note(text)
                n += 1
            except Exception:
                pass
    return n


def steer_log(task_id: str) -> list:
    """只读副本（测试/调试用）。"""
    return list(_STEER_LOG.get(task_id, ()))


def clear(task_id: str) -> None:
    """任务结束清理：agent 注册 + steer 日志。"""
    _ACTIVE_AGENTS.pop(task_id, None)
    _STEER_LOG.pop(task_id, None)
