# -*- coding: utf-8 -*-
"""失败自恢复环（_stuck_recovery）：循环卡死检测 + 简报重注入 + ENOENT 恢复。
治 m3-s2 型"文件缺失→反复 ls/cat 空转"与 m6-s1 型"15 连发相同调用"。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.executor import InhouseAgent


def _agent():
    a = InhouseAgent(runtime=None)
    a.messages = [{"role": "user", "content": "TASK: run hashcat on /w/nt.txt, save to /w/pw.txt"}]
    return a


def _sys_count(a):
    return sum(1 for m in a.messages if m.get("role") == "user" and "[SYSTEM]" in str(m.get("content", "")))


def test_repeat_streak_escalates_at_3():
    a = _agent()
    for i in range(2):
        a._stuck_recovery("terminal", "repeat warn", {"stdout": "same output"})
        assert _sys_count(a) == 0  # 2 次不触发
    a._stuck_recovery("terminal", "repeat warn", {"stdout": "same output"})
    assert _sys_count(a) == 1     # 第 3 次触发重定向
    assert "ORIGINAL TASK BRIEF" in a.messages[-1]["content"]  # 简报重注入
    assert "hashcat" in a.messages[-1]["content"]
    # 触发后 streak 重置：再连 2 次不重复注入
    a._stuck_recovery("terminal", "repeat warn", {"stdout": "x"})
    a._stuck_recovery("terminal", "repeat warn", {"stdout": "x"})
    assert _sys_count(a) == 1


def test_no_warn_resets_streak():
    a = _agent()
    a._stuck_recovery("terminal", "warn", {"stdout": "a"})
    a._stuck_recovery("terminal", "warn", {"stdout": "a"})
    a._stuck_recovery("terminal", None, {"stdout": "different"})  # 重置
    a._stuck_recovery("terminal", "warn", {"stdout": "a"})
    a._stuck_recovery("terminal", "warn", {"stdout": "a"})
    assert _sys_count(a) == 0  # 重置后未达 3 连


def test_enoent_loop_triggers_once_per_path():
    a = _agent()
    a._stuck_recovery("bash", None, {"stdout": "cat: /tmp/m3s2/pw.txt: No such file or directory"})
    assert _sys_count(a) == 0  # 第 1 次
    a._stuck_recovery("bash", None, {"stdout": "cat: /tmp/m3s2/pw.txt: No such file or directory"})
    assert _sys_count(a) == 1  # 第 2 次触发
    assert "FILE-MISSING LOOP" in a.messages[-1]["content"]
    assert "/tmp/m3s2/pw.txt" in a.messages[-1]["content"]
    a._stuck_recovery("bash", None, {"stdout": "cat: /tmp/m3s2/pw.txt: No such file or directory"})
    assert _sys_count(a) == 1  # 同路径只提醒一次
    # 不同路径独立计数
    a._stuck_recovery("bash", None, {"stdout": "ls: cannot access '/work/step2/f.log': No such file or directory"})
    a._stuck_recovery("bash", None, {"stdout": "ls: cannot access '/work/step2/f.log': No such file or directory"})
    assert _sys_count(a) == 2


def test_nudge_cap_prevents_spam():
    a = _agent()
    # 打满上限（4 条 SYSTEM 提示）
    for i in range(10):
        a._stuck_recovery("terminal", "w", {"stdout": "ls: cannot access '/p%d.log': No such file or directory" % i})
        a._stuck_recovery("terminal", "w", {"stdout": "ls: cannot access '/p%d.log': No such file or directory" % i})
    assert _sys_count(a) <= 4


def test_normal_output_no_injection():
    a = _agent()
    a._stuck_recovery("terminal", None, {"stdout": "SUCCESS password=x\nm4s3: 61d6e17b-..."})
    assert _sys_count(a) == 0
