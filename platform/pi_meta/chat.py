"""交互式对话层：豆包式 SSE 流式端点 + 会话管理。

挂载到 FastAPI (pi_meta/app.py)。
端点：
  POST   /api/chat/{session_id}/message  — 发消息，返回 SSE 流
  GET    /api/chat/{session_id}/history   — 取历史
  DELETE /api/chat/{session_id}          — 删会话
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse

from agents.executor import InhouseAgent, _Memory
from config import PIMETA_DB_PATH

DB_PATH = PIMETA_DB_PATH

# ---------------------------------------------------------------------------
# 会话存储
# ---------------------------------------------------------------------------

def _db() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)

def create_session(user_id: str = "default") -> str:
    sid = f"chat-{uuid4().hex[:12]}"
    conn = _db()
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS chat_sessions (
            session_id TEXT PRIMARY KEY, user_id TEXT, created_at TEXT, updated_at TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT, role TEXT, content TEXT, created_at TEXT,
            FOREIGN KEY(session_id) REFERENCES chat_sessions(session_id))""")
        conn.execute("INSERT OR REPLACE INTO chat_sessions(session_id,user_id,created_at,updated_at) VALUES(?,?,?,?)",
                     (sid, user_id, time.strftime("%Y-%m-%dT%H:%M:%S"), time.strftime("%Y-%m-%dT%H:%M:%S")))
        conn.commit()
    finally:
        conn.close()
    return sid

def get_session_history(session_id: str) -> List[Dict[str, str]]:
    conn = _db()
    try:
        rows = conn.execute("SELECT role,content,created_at FROM chat_messages WHERE session_id=? ORDER BY id", (session_id,)).fetchall()
    finally:
        conn.close()
    return [{"role": r[0], "content": r[1], "created_at": r[2]} for r in rows]

def append_message(session_id: str, role: str, content: str):
    conn = _db()
    try:
        conn.execute("INSERT INTO chat_messages(session_id,role,content,created_at) VALUES(?,?,?,?)",
                     (session_id, role, content, time.strftime("%Y-%m-%dT%H:%M:%S")))
        conn.execute("UPDATE chat_sessions SET updated_at=? WHERE session_id=?", (time.strftime("%Y-%m-%dT%H:%M:%S"), session_id))
        conn.commit()
    finally:
        conn.close()

def delete_session(session_id: str):
    conn = _db()
    try:
        conn.execute("DELETE FROM chat_messages WHERE session_id=?", (session_id,))
        conn.execute("DELETE FROM chat_sessions WHERE session_id=?", (session_id,))
        conn.commit()
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# SSE 流式执行器
# ---------------------------------------------------------------------------

async def run_chat_stream(session_id: str, message: str, target: str = ""):
    """SSE 流式生成器。每条 tool call / 文字实时推送。"""
    agent = InhouseAgent()
    # 注入对话历史到记忆（短期记忆）
    history = get_session_history(session_id)
    for h in history[-10:]:  # 最近 10 轮
        agent.memory.set(f"chat_hist_{h['role']}", h["content"][:500])

    append_message(session_id, "user", message)

    # 构建 task 文本
    task = message
    if target:
        task = f"Target: {target}\n\n{message}"

    turn = 0
    try:
        async for event in agent.run_stream(task, target=target):
            # event = {"type": "text"|"tool", "content": "..."}
            append_message(session_id, "assistant", event["content"][:2000])
            yield f"data: {json.dumps(event)}\n\n"
            turn += 1
            if turn > 100:
                break
    except Exception as e:
        yield f"data: {json.dumps({'type':'error','content':str(e)})}\n\n"
    finally:
        append_message(session_id, "assistant", f"[done after {turn} turns]")

# ---------------------------------------------------------------------------
# FastAPI 路由
# ---------------------------------------------------------------------------

def register_chat_routes(app: FastAPI):
    @app.post("/api/chat/{session_id}/message")
    async def chat_message(session_id: str, body: Dict[str, Any]):
        message = body.get("message", "")
        target = body.get("target", "")
        if not message.strip():
            raise HTTPException(400, "message is required")
        # 异步执行，不阻塞
        asyncio.create_task(_process_chat(session_id, message, target))
        return {"session_id": session_id, "status": "processing"}

    @app.get("/api/chat/{session_id}/history")
    async def chat_history(session_id: str):
        return {"session_id": session_id, "messages": get_session_history(session_id)}

    @app.delete("/api/chat/{session_id}")
    async def chat_delete(session_id: str):
        delete_session(session_id)
        return {"session_id": session_id, "status": "deleted"}

    @app.post("/api/chat")
    async def chat_new(body: Dict[str, Any]):
        sid = create_session(body.get("user_id", "default"))
        return {"session_id": sid}


async def _process_chat(session_id: str, message: str, target: str):
    """后台任务：执行 agent 并逐条写入消息。"""
    gen = run_chat_stream(session_id, message, target)
    async for event in gen:
        pass  # 已通过 append_message 持久化
