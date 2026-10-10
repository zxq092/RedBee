"""④ 工具门控（skill-gated tools，借 ARTEX）测试。

覆盖：核心集排除门控工具、schema 缩减、模块自动解锁（sqli/generic）、
运行时 load_skill 解锁（结果带 unlocked_tools、下一轮 schema 生效）、
未知 skill 不解锁、遗留工具永不可见、prompt 工具列表与 schema 一致。
"""
from __future__ import annotations

import asyncio
import json

import pytest

from agents.executor import GATED_TOOLS, TOOL_UNLOCK_MAP, InhouseAgent, build_tools_schema
from agents.tools import TOOL_REGISTRY

# 核心必在（任何 agent 开箱即用）
_CORE_ESSENTIALS = {"http_request", "web_get_contents", "kb_query", "submit_finding",
                    "record_coverage", "poc_verify", "bash", "terminal", "exec_command",
                    "python", "memory", "done", "load_skill", "list_skills",
                    "query_tool_output", "todo_write", "create_note"}
# 门控代表
_SQLI = {"sqlmap", "sqlmap_exploit"}
_RECON = {"nmap", "nikto", "fofa_search", "zoomeye_search", "list_sitemap"}
_LEGACY = {"store_answer", "store_code", "store_guide", "search_guide", "search_answer",
           "search_in_memory", "advice", "ask", "ask_user",
           "subtask_list", "subtask_patch", "finish_scan", "report_result"}


def _schema_names(agent: InhouseAgent) -> set:
    return {t["function"]["name"] for t in agent.tools_schema}


def test_core_schema_excludes_gated():
    a = InhouseAgent()
    names = _schema_names(a)
    assert not (names & GATED_TOOLS)
    assert _CORE_ESSENTIALS <= names
    assert names == set(TOOL_REGISTRY) - GATED_TOOLS


def test_schema_size_reduced():
    a = InhouseAgent()
    gated_chars = len(json.dumps(a.tools_schema, ensure_ascii=False))
    full_chars = len(json.dumps(build_tools_schema(), ensure_ascii=False))
    assert gated_chars < full_chars * 0.6  # 至少省 40%


def test_auto_unlock_sqli_at_build():
    a = InhouseAgent()
    a._build_initial_messages("http://t", "sqli", "test sqli on http://t")
    assert _SQLI <= _schema_names(a)
    b = InhouseAgent()
    b._build_initial_messages("http://t", "xss", "test xss on http://t")
    assert not (_SQLI & _schema_names(b))


def test_auto_unlock_generic_recon():
    a = InhouseAgent()
    a._build_initial_messages("http://t", "generic", "pre recon")
    assert _RECON <= _schema_names(a)
    # browser 不随 generic 解锁（走 agent_browser skill）
    assert "browser" not in _schema_names(a)


@pytest.fixture(autouse=True)
def _no_truncation(monkeypatch):
    # skill 内容 >8K 会走外置截断（非完整 JSON）；测试调大上限保证结果可解析
    monkeypatch.setenv("HINSE_TOOL_OUT_CHARS", "200000")
    yield


def _call_load_skill(agent: InhouseAgent, skill: str):
    tc = [{"id": "call_gate1", "function": {"name": "load_skill",
                                             "arguments": json.dumps({"name": skill})}}]
    before = len(agent.messages)
    asyncio.run(agent._exec_tool_calls(tc, "t-gate", "http://t"))
    tool_msg = [m for m in agent.messages[before:] if m.get("role") == "tool"]
    return json.loads(tool_msg[-1]["content"])


def test_runtime_unlock_via_load_skill():
    a = InhouseAgent()
    a._build_initial_messages("http://t", "xss", "test xss")
    assert not (_SQLI & _schema_names(a))
    result = _call_load_skill(a, "sql-injection")
    assert "error" not in result
    assert set(result.get("unlocked_tools", [])) == _SQLI
    # 下一轮 schema 已含 sqlmap（_chat 的 payload 用 self.tools_schema）
    assert _SQLI <= _schema_names(a)


def test_runtime_unlock_browser_skill():
    a = InhouseAgent()
    a._build_initial_messages("http://t", "xss", "test xss")
    result = _call_load_skill(a, "agent_browser")
    assert set(result.get("unlocked_tools", [])) == {"browser"}
    assert "browser" in _schema_names(a)


def test_unknown_skill_no_unlock():
    a = InhouseAgent()
    a._build_initial_messages("http://t", "xss", "test xss")
    before = _schema_names(a)
    result = _call_load_skill(a, "no-such-skill-xyz")
    assert "error" in result
    assert "unlocked_tools" not in result
    assert _schema_names(a) == before


def test_legacy_tools_never_visible():
    a = InhouseAgent()
    for skill in TOOL_UNLOCK_MAP:
        a._unlock(skill)
    a._auto_unlock("generic")
    a._auto_unlock("sqli")
    assert not (_LEGACY & _schema_names(a))


def test_prompt_tool_list_matches_schema():
    a = InhouseAgent()
    a._build_initial_messages("http://t", "xss", "test xss")
    system = a.messages[0]["content"]
    line = next(l for l in system.splitlines() if "Tools available via function calling:" in l)
    listed = {n.strip() for n in line.split(":", 1)[1].split(",")}
    assert listed == _schema_names(a)
    # TOOLSET 段存在（告知解锁机制）
    assert "TOOLSET (phased)" in system
    assert "load_skill('sql-injection')" in system
