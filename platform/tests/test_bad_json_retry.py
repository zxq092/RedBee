"""坏 JSON tool-call 处理回归：不执行、不烧预算、连续 2 轮注入双语纠错提示。

治 qwen 偶发吐坏 function.arguments：旧代码 JSONDecodeError 静默降级 args={}，
调用白烧预算且 LLM 不知情（借 CyberStrikeAI tool_args_json_retry 思路，
用 in-loop 纠错代替整 agent 重跑）。
"""
import asyncio
import json

import pytest

import agents.executor as ex_mod
from agents.executor import InhouseAgent, ToolDef


class _State:
    tool_calls = 0
    turn = 0


def _agent():
    a = object.__new__(InhouseAgent)
    a.messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    a.state = _State()
    a.recent_calls = []
    a.container = ""
    a.workdir = "/tmp"
    a._tool_started = {}
    a._tool_ended = {}
    a._has_recorded = False
    a._bad_json_streak = 0
    a._text_only_streak = 0
    a._current_module = "test"
    a._uid = "testuid"
    return a


def _tc(cid, name, args):
    return {"id": cid, "type": "function",
            "function": {"name": name, "arguments": args}}


@pytest.fixture
def fake_tool(monkeypatch):
    calls = []

    async def handler(cmd="", **kw):
        calls.append(cmd)
        return {"ok": cmd}

    tdef = ToolDef("fake_tool", "d", {"type": "object"}, handler, "test")
    monkeypatch.setattr(ex_mod, "get_tool",
                        lambda name: tdef if name == "fake_tool" else None)
    return calls


def test_bad_json_not_executed_no_budget(fake_tool):
    a = _agent()
    asyncio.run(a._exec_tool_calls(
        [_tc("c1", "fake_tool", '{"cmd": "x"  (truncated')], "t1", "http://t"))
    assert fake_tool == []                      # 未执行
    assert a.state.tool_calls == 0              # 不烧预算
    last = a.messages[-1]
    assert last["role"] == "tool" and last["tool_call_id"] == "c1"
    assert "not valid JSON" in last["content"]
    assert a._bad_json_streak == 1
    # 首轮不注入 user 纠错提示
    assert not any(m["role"] == "user" and "invalid JSON" in (m.get("content") or "")
                   for m in a.messages[2:])


def test_bad_json_two_rounds_injects_reminder(fake_tool):
    a = _agent()
    bad = [_tc("c1", "fake_tool", '{"broken"')]
    asyncio.run(a._exec_tool_calls(bad, "t1", "http://t"))
    asyncio.run(a._exec_tool_calls(bad, "t1", "http://t"))
    assert a._bad_json_streak == 2
    reminders = [m for m in a.messages if m["role"] == "user"
                 and "invalid JSON" in (m.get("content") or "")]
    assert len(reminders) == 1
    assert "JSON" in reminders[0]["content"]    # 双语纠错提示


def test_valid_call_resets_streak(fake_tool):
    a = _agent()
    bad = [_tc("c1", "fake_tool", '{"broken"')]  # noqa: E501
    good = [_tc("c2", "fake_tool", json.dumps({"cmd": "hi"}))]
    asyncio.run(a._exec_tool_calls(bad, "t1", "http://t"))
    asyncio.run(a._exec_tool_calls(good, "t1", "http://t"))
    assert a._bad_json_streak == 0
    assert fake_tool == ["hi"]                  # 合法调用正常执行
    assert a.state.tool_calls == 1
    # 再坏一轮不触发提示（streak 已重置）
    asyncio.run(a._exec_tool_calls(bad, "t1", "http://t"))
    assert not any(m["role"] == "user" and "invalid JSON" in (m.get("content") or "")
                   for m in a.messages)


def test_stream_bad_json_yields_error_event(monkeypatch, fake_tool):
    a = _agent()
    bad = [_tc("c1", "fake_tool", '{"broken"')]

    async def collect():
        evs = []
        async for e in a._exec_tool_calls_stream(bad, "t1", "http://t"):
            evs.append(e)
        return evs

    evs = asyncio.run(collect())
    assert evs and evs[0]["type"] == "tool"
    assert "not valid JSON" in json.dumps(evs[0]["detail"])
    assert a.state.tool_calls == 0
