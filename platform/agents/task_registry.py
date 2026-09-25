"""任务级取消：登记一个 task 名下所有 asyncio 任务（bg/slot/child），统一 cancel + 物理杀沙箱容器。

为什么需要：asyncio task.cancel() 只终止等待链；真正的攻击载体是 Kali 沙箱容器
（inhouse-sess-XX，攻击命令在里面跑）+ 宿主机 docker exec 客户端。
stop = 标记 cancelled + cancel 所有登记任务 + docker rm -f 该 task 名下全部沙箱。
"""
from __future__ import annotations

import asyncio
from typing import Dict, List, Optional, Set

_CANCELLED: Set[str] = set()
_TASK_TASKS: Dict[str, Set["asyncio.Task"]] = {}
# 飞行中指令（in-run steer）：task_id -> 运行中 agent 集合 / 相位间隙的待发指令缓冲
_ACTIVE_AGENTS: Dict[str, set] = {}
_PENDING_NOTES: Dict[str, List[str]] = {}


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
# ---------------------------------------------------------------------------

def register_agent(task_id: str, agent) -> None:
    """登记一个运行中的 agent 实例（InhouseAgent）。新 agent 诞生时自动吃进相位间隙积压的指令。"""
    if not task_id or agent is None:
        return
    _ACTIVE_AGENTS.setdefault(task_id, set()).add(agent)
    pending = _PENDING_NOTES.pop(task_id, None)
    if pending:
        for t in pending:
            try:
                agent.inject_note(t)
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


def active_agents(task_id: str) -> list:
    return list(_ACTIVE_AGENTS.get(task_id, ()))


def add_note(task_id: str, text: str) -> int:
    """注入一条飞行中指令：有运行中 agent → 立即注入并返回数量；
    相位间隙（无 agent 在跑）→ 进缓冲，返回 0（下一个 agent 诞生时自动吃进）。"""
    text = (text or "").strip()
    if not task_id or not text:
        return 0
    s = _ACTIVE_AGENTS.get(task_id)
    if s:
        n = 0
        for a in list(s):
            try:
                a.inject_note(text)
                n += 1
            except Exception:
                pass
        return n
    _PENDING_NOTES.setdefault(task_id, []).append(text)
    return 0


def clear(task_id: str) -> None:
    """任务结束清理：agent 注册 + 缓冲指令。"""
    _ACTIVE_AGENTS.pop(task_id, None)
    _PENDING_NOTES.pop(task_id, None)
