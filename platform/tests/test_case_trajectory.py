"""regression: _case_tool_calls 必须返回"已完成(拿到结果)"的工具调用，而非未配对调用。"""
import json
import pytest
from agents.executor import InhouseAgent


def _agent_with_msgs():
    a = object.__new__(InhouseAgent)
    a._tool_started = {"c1": "s1"}
    a._tool_ended = {"c1": "e1"}
    a.messages = [
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c1", "function": {"name": "bash", "arguments": json.dumps({"cmd": "id"})}}]},
        {"role": "tool", "tool_call_id": "c1", "content": '{"returncode": 0, "stdout": "uid=0"}'},
    ]
    return a


def test_case_tool_calls_returns_completed():
    a = _agent_with_msgs()
    calls = a._case_tool_calls()
    assert len(calls) == 1
    assert calls[0]["name"] == "bash"
    assert calls[0]["result"]["stdout"] == "uid=0"  # 拿到结果的关键调用被保留


def test_case_tool_calls_drops_unmatched_only_as_tail():
    """未配对调用（被 compaction 截断掉 tool 结果）只能排在末尾，不能挤掉已完成。"""
    a = _agent_with_msgs()
    # 追加一个只有 assistant 调用、没有 tool 结果的（被截断）
    a.messages.append({"role": "assistant", "content": "", "tool_calls": [
        {"id": "c9", "function": {"name": "http_request", "arguments": json.dumps({"url": "x"})}}]})
    calls = a._case_tool_calls()
    assert calls[0]["name"] == "bash"          # 已完成的第一
    assert calls[0]["result"]["stdout"] == "uid=0"
    assert calls[-1]["name"] == "http_request"  # 未配对的排末尾，不带 result
    assert "result" not in calls[-1]
