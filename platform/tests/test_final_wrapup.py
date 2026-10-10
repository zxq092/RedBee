"""预算耗尽强制收口总结回归：LLM 优先，LLM 挂死降级 DB 机械总结，summary 进 case snapshot。"""
import asyncio

from agents.executor import InhouseAgent, build_inhouse_case_snapshot


class _State:
    tool_calls = 0
    turn = 0


def _agent():
    a = object.__new__(InhouseAgent)
    a.messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    a.state = _State()
    a.last_task_id = "t-wrap"
    a._current_module = "test"
    a._compact_messages = lambda: None
    a.final_summary = ""
    a._exit_reason = "budget"
    return a


def test_wrapup_llm_path():
    a = _agent()

    async def fake_chat(messages, max_tokens=4096, temperature=0.3, runtime=None):
        assert any("FINAL WRAP-UP" in (m.get("content") or "") for m in messages)
        return {"content": "FINAL: 1 confirmed sqli. END", "tool_calls": None}

    a._chat = fake_chat
    out = asyncio.run(a._final_wrapup(None, "t", "http://t"))
    assert out == "FINAL: 1 confirmed sqli. END"


def test_wrapup_llm_dead_falls_back_mechanical():
    a = _agent()

    async def fake_chat(messages, max_tokens=4096, temperature=0.3, runtime=None):
        raise RuntimeError("all available model runtimes failed")

    a._chat = fake_chat
    a._case_db_rows = lambda: (
        [{"severity": "high", "status": "found", "title": "SQLi on /vuln"}],
        [{"outcome": "reported"}, {"outcome": "ruled_out"}],
    )
    out = asyncio.run(a._final_wrapup(None, "t", "http://t"))
    assert "FINAL SUMMARY" in out
    assert "SQLi on /vuln" in out
    assert "reported=1" in out and "ruled_out=1" in out


def test_wrapup_tool_calls_ignored_falls_back():
    # LLM 返回 tool_calls 而非纯文本 → 视同无效，降级机械总结
    a = _agent()

    async def fake_chat(messages, max_tokens=4096, temperature=0.3, runtime=None):
        return {"content": "", "tool_calls": [{"id": "x", "function": {}}]}

    a._chat = fake_chat
    a._case_db_rows = lambda: ([], [])
    out = asyncio.run(a._final_wrapup(None, "t", "http://t"))
    assert "FINAL SUMMARY" in out


def test_summary_in_case_snapshot():
    s = build_inhouse_case_snapshot(
        task_id="t", target="http://t", target_id="t",
        model="m", runtime_id="r", summary="WRAPPED CONCLUSION")
    assert s.summary == "WRAPPED CONCLUSION"
    s2 = build_inhouse_case_snapshot(
        task_id="t", target="http://t", target_id="t", model="m", runtime_id="r")
    assert s2.summary == ""
