"""坏参数 tool-call 一轮自愈（_validate_tool_calls / _try_repair_calls）。

实测动机（2026-10-20 批次复盘）：locktalk DeepSeek 时代 57 次 "missing required X"
（26% 轮次浪费）、failproof 75/220（34%）——错误回传+下轮重试每次烧一整轮。
自愈路径：本地预校验 → 无效则一次仅修复调用（不进主历史）→ 修复成功用新批次。
"""
import json

import pytest

from agents.executor import _validate_tool_calls, _required_params
from agents.tools import get_tool


def _call(name, arguments):
    return {"id": "c1", "function": {"name": name, "arguments": arguments}}


def test_validate_ok():
    calls = [_call("bash", json.dumps({"cmd": "ls"}))]
    assert _validate_tool_calls(calls) == []


def test_validate_missing_required():
    calls = [_call("python", "{}")]
    problems = _validate_tool_calls(calls)
    assert len(problems) == 1 and "code" in problems[0]


def test_validate_bad_json():
    calls = [_call("bash", "{'cmd': 'ls',}")]  # 单引号+尾逗号，非严格 JSON
    problems = _validate_tool_calls(calls)
    assert any("JSON" in p for p in problems)


def test_validate_unknown_tool():
    calls = [_call("submit_fining", "{}")]
    assert any("unknown tool" in p for p in _validate_tool_calls(calls))


def test_validate_injected_params_not_required():
    # container/workdir/task_id 由执行器注入，不要求模型提供
    tdef = get_tool("bash")
    req = _required_params(tdef)
    assert "cmd" in req
    calls = [_call("bash", json.dumps({"cmd": "id"}))]
    assert _validate_tool_calls(calls) == []


@pytest.mark.asyncio
async def test_repair_replaces_invalid_batch(monkeypatch):
    """坏批次 → 一次修复调用 → 返回修复后的批次；修复对话不进主 messages。"""
    from agents.executor import InhouseAgent

    a = InhouseAgent.__new__(InhouseAgent)  # 绕过 __init__（不建容器）
    a.messages = [{"role": "user", "content": "t"}]
    a._repair_budget = 2
    a.last_task_id = "t-test"
    a._current_module = "objective"

    bad = [_call("python", "{}")]
    good = [_call("python", json.dumps({"code": "print(1)"}))]

    async def fake_chat(messages, **kw):
        assert any("ARG REPAIR" in str(m.get("content", "")) for m in messages)
        return {"role": "assistant", "content": "", "tool_calls": good}

    a._chat = fake_chat
    out = await a._try_repair_calls(bad, runtime=None)
    assert out == good
    assert len(a.messages) == 1  # 修复对话未污染主历史
    assert a._repair_budget == 1


@pytest.mark.asyncio
async def test_repair_fallback_on_failure(monkeypatch):
    """修复调用失败/仍无效 → 原样返回（走既有错误路径，永不更差）。"""
    from agents.executor import InhouseAgent

    a = InhouseAgent.__new__(InhouseAgent)
    a.messages = []
    a._repair_budget = 2
    a.last_task_id = ""
    a._current_module = ""

    bad = [_call("python", "{}")]

    async def fake_chat(messages, **kw):
        return {"role": "assistant", "content": "still broken", "tool_calls": bad}

    a._chat = fake_chat
    assert await a._try_repair_calls(bad, runtime=None) == bad

    async def boom(messages, **kw):
        raise RuntimeError("llm down")

    a._chat = boom
    assert await a._try_repair_calls(bad, runtime=None) == bad


@pytest.mark.asyncio
async def test_repair_budget_exhausted(monkeypatch):
    from agents.executor import InhouseAgent

    a = InhouseAgent.__new__(InhouseAgent)
    a.messages = []
    a._repair_budget = 0
    a.last_task_id = ""
    a._current_module = ""

    called = {"n": 0}

    async def fake_chat(messages, **kw):
        called["n"] += 1
        return {}

    a._chat = fake_chat
    bad = [_call("python", "{}")]
    assert await a._try_repair_calls(bad, runtime=None) == bad
    assert called["n"] == 0  # 预算耗尽不再发起修复调用
