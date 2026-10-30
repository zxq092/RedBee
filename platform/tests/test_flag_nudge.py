# -*- coding: utf-8 -*-
"""CTF 工具流 flag 识别提醒（_flag_nudge）：提交纪律兜底。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.executor import InhouseAgent, _flag_nudge_patterns


def _agent():
    return InhouseAgent(runtime=None)


def _nudge_count(a):
    return sum(1 for m in a.messages if m.get("role") == "user" and "FLAG CANDIDATE" in str(m.get("content", "")))


def test_uuid_v4_triggers_nudge_once():
    a = _agent()
    a._ctf_flag_watch = True
    a._flag_nudge("terminal", {"stdout": "SUCCESS password=x\nm4s3: 61d6e17b-bd3b-4c7f-94ae-37b824eaa779"})
    assert _nudge_count(a) == 1
    # 同一 UUID 第二次出现不再提醒（去重）
    a._flag_nudge("terminal", {"stdout": "again 61d6e17b-bd3b-4c7f-94ae-37b824eaa779"})
    assert _nudge_count(a) == 1


def test_non_v4_uuid_no_nudge():
    a = _agent()
    a._ctf_flag_watch = True
    # task_id 形态（32 hex 无分隔）与非 v4 UUID 不触发
    a._flag_nudge("terminal", {"stdout": "tabaef51a964b4a84bfe0b749edae5493 550e8400-e29b-11d4-a716-446655440000"})
    assert _nudge_count(a) == 0


def test_ctf_prefix_pattern_triggers():
    a = _agent()
    a._ctf_flag_watch = True
    a._flag_nudge("bash", {"stdout": "here: HTB{D3v3l0p3r_t00l5}"})
    assert _nudge_count(a) == 1


def test_watch_off_and_submit_exempt():
    a = _agent()
    a._flag_nudge("terminal", {"stdout": "61d6e17b-bd3b-4c7f-94ae-37b824eaa779"})
    assert _nudge_count(a) == 0  # 非 CTF 模式不提醒
    a._ctf_flag_watch = True
    a._flag_nudge("submit_finding", {"ok": True, "uuid": "61d6e17b-bd3b-4c7f-94ae-37b824eaa779"})
    assert _nudge_count(a) == 0  # 提交类工具豁免


def test_max_two_per_result():
    a = _agent()
    a._ctf_flag_watch = True
    blob = " ".join(f"61d6e17b-bd3b-4c{i:01x}f-94ae-37b824eaa7{i:02x}" for i in range(5))
    a._flag_nudge("terminal", {"stdout": blob})
    assert _nudge_count(a) == 2  # 单次结果最多 2 条提醒


def test_patterns_compiled():
    pats = _flag_nudge_patterns()
    assert pats, "至少应有 UUIDv4 模式"


def test_task_text_uuids_exempt():
    a = _agent()
    a._ctf_flag_watch = True
    a.messages = [{"role": "user", "content": "creds: 0d528ba4-3f7e-460e-9565-1d47f1da116d go"}]
    a._flag_nudge("terminal", {"stdout": "login ok with 0d528ba4-3f7e-460e-9565-1d47f1da116d"})
    assert _nudge_count(a) == 0
    a._flag_nudge("terminal", {"stdout": "found 4796df35-149d-4c10-9c6e-ac2ef46945af"})
    assert _nudge_count(a) == 1
