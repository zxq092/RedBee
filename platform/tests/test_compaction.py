"""P0/P1 上下文压缩回归测试：闸口径一致 + assistant tool_calls 可压 + API 配对不断裂。

R7 实证：旧闸只量 content（tool_calls 不可见）+ 只压 tool 输出（assistant tool_calls
形成压不下的地板）→ csrf 模块 ctx 冲到 1.07M chars（预算 80K，13 倍）。
"""
import json

from agents.executor import InhouseAgent


def _agent_with_messages(messages):
    a = object.__new__(InhouseAgent)
    a.messages = messages
    return a


def _round(i, args_len=5000, out_len=8000):
    """一轮：assistant(content + tool_calls[大参数]) + tool(大输出)。"""
    call_id = f"call_{i}"
    assistant = {
        "role": "assistant",
        "content": f"turn {i} reasoning " + "x" * 100,
        "tool_calls": [{
            "id": call_id,
            "type": "function",
            "function": {"name": "bash", "arguments": json.dumps({"cmd": "a" * args_len})},
        }],
    }
    tool = {"role": "tool", "tool_call_id": call_id, "content": "o" * out_len}
    return assistant, tool


def _msgs(n_rounds):
    msgs = [{"role": "system", "content": "s" * 2000},
            {"role": "user", "content": "u" * 3000}]
    for i in range(n_rounds):
        a, t = _round(i)
        msgs += [a, t]
    return msgs


def test_context_size_includes_tool_calls():
    # P0：闸口径 = content + tool_calls（与 _chat 发送口径一致）
    a = _agent_with_messages(_msgs(1))
    sys_len, user_len = 2000, 3000
    assistant = a.messages[2]
    tool = a.messages[3]
    expected = (sys_len + user_len
                + len(assistant["content"]) + sum(len(str(tc)) for tc in assistant["tool_calls"])
                + len(tool["content"]))
    assert a._context_size() == expected


def test_compaction_bounds_context_to_budget():
    # P0+P1：30 轮大上下文（~400K chars）必须被压到 80K 预算内
    a = _agent_with_messages(_msgs(30))
    assert a._context_size() > 400000
    a._compact_messages()
    assert a._context_size() <= 80000


def test_compaction_preserves_api_pairing():
    # 压缩后：每个 tool 结果的 tool_call_id 仍能在 assistant tool_calls 里找到（配对不断裂）
    a = _agent_with_messages(_msgs(30))
    a._compact_messages()
    call_ids = {tc["id"] for m in a.messages if m.get("role") == "assistant"
                for tc in (m.get("tool_calls") or [])}
    tool_ids = {m["tool_call_id"] for m in a.messages if m.get("role") == "tool"}
    assert tool_ids <= call_ids
    # id 未被改写
    assert all(str(i).startswith("call_") for i in call_ids)


def test_compaction_keeps_recent_turn_intact():
    # 从最老压起：最新一轮的 tool 输出与 tool_calls 参数保持原样
    a = _agent_with_messages(_msgs(30))
    a._compact_messages()
    last_tool = a.messages[-1]
    assert len(last_tool["content"]) >= 8000
    last_assistant = a.messages[-2]
    tc = last_assistant["tool_calls"][0]
    assert len(str(tc["function"]["arguments"])) > 200
    # system + 首条 user 不动
    assert a.messages[0]["content"] == "s" * 2000
    assert a.messages[1]["content"] == "u" * 3000


def test_compaction_noop_under_budget():
    # 预算内不压：短历史原样
    a = _agent_with_messages(_msgs(1))
    snapshot = json.dumps(a.messages)
    a._compact_messages()
    assert json.dumps(a.messages) == snapshot


def test_compacted_args_stay_valid_json():
    # 占位符必须是合法 JSON（部分 chat template 会 json.loads arguments）
    a = _agent_with_messages(_msgs(30))
    a._compact_messages()
    for m in a.messages:
        for tc in (m.get("tool_calls") or []):
            json.loads(tc["function"]["arguments"])
