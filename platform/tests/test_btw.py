"""⑤ /btw 旁路提问测试（pi_meta/btw）。

覆盖：深快照语义（主循环改原对象不影响回答）、payload 无 tools、
选 agent（module 优先/上下文最大/回落）、LLM 成功/失败/超时、
不写回 agent 上下文、无 agent/空上下文报错。
"""
from __future__ import annotations

import asyncio
import os
from contextlib import contextmanager

import pytest

from agents.executor import InhouseAgent
from agents import task_registry
from pi_meta import btw
from pi_meta.model_runtime import ChatResult, ModelRuntime, ModelRuntimeError, coerce_resolved_runtime

_FAKE_RUNTIME = coerce_resolved_runtime(
    ModelRuntime("m-test", "http://m.test/v1", "FAKE_MODEL_KEY", 5, 5, "/v1/models", "t"))


class _State:
    def __init__(self, turn=3, tool_calls=7):
        self.turn = turn
        self.tool_calls = tool_calls


def _agent(messages, module="sqli", uid="ab12cd34", runtime=None):
    a = object.__new__(InhouseAgent)
    a.messages = messages
    a.state = _State()
    a.last_task_id = "t-btw"
    a._current_module = module
    a._uid = uid
    a.runtime = runtime if runtime is not None else _FAKE_RUNTIME
    return a


@contextmanager
def _register(task_id, *agents):
    for a in agents:
        task_registry.register_agent(task_id, a, a._current_module)
    yield
    for a in agents:
        task_registry.unregister_agent(task_id, a)


@pytest.fixture(autouse=True)
def _clean_registry():
    yield
    task_registry.clear("t-btw")


def _msgs(n=2, base="hello"):
    return [{"role": "system", "content": "sys"},
            *[{"role": "user", "content": f"{base}{i}"} for i in range(n)]]


# ---- 快照与 payload ----

def test_snapshot_is_immutable_to_main_loop():
    orig = _msgs()
    snap = btw.snapshot_messages(orig)
    # 主循环继续原地改：改内容 + 追加消息
    orig[1]["content"] = "MUTATED"
    orig.append({"role": "assistant", "content": "later"})
    assert snap[1]["content"] == "hello0"
    assert len(snap) == 3  # system + 2
    assert all("MUTATED" not in str(m) for m in snap)


def test_snapshot_fallback_for_unserializable_content():
    weird = [{"role": "user", "content": object()}]  # 不可 JSON 序列化 → 逐条浅拷贝兜底
    snap = btw.snapshot_messages(weird)
    assert len(snap) == 1 and isinstance(snap[0]["content"], str)


def test_payload_has_no_tools_and_appends_question():
    snap = btw.snapshot_messages(_msgs())
    payload = btw.build_btw_payload(snap, "what did you find?")
    assert "tools" not in payload
    assert payload["messages"][:len(snap)] == snap
    last = payload["messages"][-1]
    assert last["role"] == "user"
    assert "what did you find?" in last["content"]
    assert "do NOT call any tools" in last["content"]
    assert payload["max_tokens"] == 1024


# ---- 选 agent ----

def test_pick_agent_by_module_then_most_informed():
    small = _agent(_msgs(1), module="sqli")
    big = _agent(_msgs(5, base="x" * 100), module="xss")
    small_task = _agent(_msgs(3), module=None)
    assert btw.pick_agent([small, big], "xss") is big
    assert btw.pick_agent([small, big], "sqli") is small
    # 未指定 → 上下文最大
    assert btw.pick_agent([small, big, small_task]) is big
    # 指定模块未命中 → 回落到全局最大
    assert btw.pick_agent([small, big], "upload") is big
    assert btw.pick_agent([]) is None


# ---- answer() 集成 ----

def _mock_chat(monkeypatch, content="all good", ok=True, error_code="AUTH_ERROR"):
    captured = {}

    async def fake_chat(resolved, payload):
        captured["resolved"] = resolved
        captured["payload"] = payload
        if ok:
            return ChatResult(True, content, [], "rt-x", [], None)
        return ChatResult(False, "", [], "rt-x", [],
                          ModelRuntimeError(error_code, "chat", "m", "boom"))

    monkeypatch.setattr("pi_meta.btw.RuntimeClient.chat", fake_chat)
    return captured


@pytest.mark.asyncio
async def test_answer_happy_path_does_not_touch_agent_context(monkeypatch):
    a = _agent(_msgs(2))
    with _register("t-btw", a):
        captured = _mock_chat(monkeypatch, content="I found a sqli on /login")
        out = await btw.answer("t-btw", "what did you find?")
    assert out["ok"] is True
    assert out["answer"] == "I found a sqli on /login"
    assert out["agent"]["module"] == "sqli"
    assert out["agent"]["n_messages"] == 3  # system + 2
    assert out["agent"]["turn"] == 3 and out["agent"]["tool_calls"] == 7
    # 发给 LLM 的：快照 + 旁路提问，无 tools
    assert "tools" not in captured["payload"]
    assert "what did you find?" in captured["payload"]["messages"][-1]["content"]
    # 主循环上下文未被污染（没追加 btw 问题、没改原消息）
    assert len(a.messages) == 3
    assert not any("btw" in str(m.get("content", "")).lower() for m in a.messages)


@pytest.mark.asyncio
async def test_answer_selects_module_agent(monkeypatch):
    sqli = _agent(_msgs(2, base="sqli-"), module="sqli")
    xss = _agent(_msgs(4, base="xss-" * 50), module="xss")
    with _register("t-btw", sqli, xss):
        _mock_chat(monkeypatch)
        out = await btw.answer("t-btw", "q", module="sqli")
    assert out["ok"] and out["agent"]["module"] == "sqli"
    assert out["agent"]["n_messages"] == 3  # 选的是小上下文 sqli 专员，不是最大的 xss


@pytest.mark.asyncio
async def test_answer_no_active_agent(monkeypatch):
    _mock_chat(monkeypatch)
    out = await btw.answer("t-none", "q")
    assert out["ok"] is False
    assert "no active agent" in out["error"]


@pytest.mark.asyncio
async def test_answer_empty_context(monkeypatch):
    a = _agent([], module="sqli")
    with _register("t-btw", a):
        calls = []

        async def fake_chat(resolved, payload):
            calls.append(1)

        monkeypatch.setattr("pi_meta.btw.RuntimeClient.chat", fake_chat)
        out = await btw.answer("t-btw", "q")
    assert out["ok"] is False and "empty" in out["error"]
    assert calls == []  # 空上下文不发 LLM


@pytest.mark.asyncio
async def test_answer_llm_failure_is_reported_not_raised(monkeypatch):
    a = _agent(_msgs(2))
    with _register("t-btw", a):
        _mock_chat(monkeypatch, ok=False)
        out = await btw.answer("t-btw", "q")
    assert out["ok"] is False
    assert out["error"] == "boom"
    assert out["agent"]["uid"] == "ab12cd34"


@pytest.mark.asyncio
async def test_answer_timeout(monkeypatch):
    a = _agent(_msgs(2))
    monkeypatch.setenv("BTW_TIMEOUT", "1")

    async def slow_chat(resolved, payload):
        await asyncio.sleep(int(os.environ["BTW_TIMEOUT"]) + 1)

    monkeypatch.setattr("pi_meta.btw.RuntimeClient.chat", slow_chat)
    with _register("t-btw", a):
        out = await btw.answer("t-btw", "q")
    assert out["ok"] is False
    assert "timed out" in out["error"]


@pytest.mark.asyncio
async def test_answer_empty_question():
    out = await btw.answer("t-btw", "   ")
    assert out["ok"] is False and out["error"] == "question required"
