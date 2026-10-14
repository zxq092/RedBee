""".pwn 程序级利用执行域（M1 地基）：planner 模块 + skill 映射 + 门控原生工具族 + 自动解锁。"""
import pytest
from agents.executor import GATED_TOOLS, TOOL_UNLOCK_MAP, InhouseAgent
from agents.tools import TOOL_REGISTRY, get_skill_content, resolve_skill_name

_NATIVE = {"native_info", "native_gdb", "native_run", "native_interact",
           "native_pwn", "native_analyze", "native_source"}


def _schema_names(agent) -> set:
    return {t["function"]["name"] for t in agent.tools_schema}


def test_native_tools_registered_and_gated():
    names = set(TOOL_REGISTRY.keys())
    assert _NATIVE <= names
    assert _NATIVE <= GATED_TOOLS  # 门控：Web agent 不裸奔


def test_core_schema_excludes_native():
    a = InhouseAgent()
    assert not (_schema_names(a) & _NATIVE)


def test_planner_has_pwn():
    from pi_meta.planner import MODULES
    assert "pwn" in MODULES


def test_skill_alias_resolves():
    assert resolve_skill_name("pwn") == "binary-exploitation"
    assert get_skill_content("pwn")


def test_pwn_auto_unlocks_native():
    a = InhouseAgent()
    a._auto_unlock("pwn")
    assert _NATIVE <= a._unlocked_tools
    # 解锁后 schema 放行（_current_tool_names = 核心 + 已解锁）
    assert _NATIVE <= _schema_names(a)


def test_unlock_map_has_binary_exploitation():
    assert _NATIVE <= (TOOL_UNLOCK_MAP.get("binary-exploitation") or set())
