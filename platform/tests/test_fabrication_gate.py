# -*- coding: utf-8 -*-
"""反幻觉 gate（_fabrication_gate）：CTF 提交的 flag 必须逐字存在于原始工具输出。

2026-10-30 Modbus 实弹：qwen 编造从未读到的 FLAG{...}（regs 0-15 实际是
"SIM-PLC-202K"），pattern 早停误判 solved。gate 在 submit_finding 前拦截。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.executor import InhouseAgent


def _agent():
    return InhouseAgent(runtime=None)


def test_hallucinated_flag_rejected():
    a = _agent()
    a._ctf_flag_watch = True
    a._record_raw_result({"stdout": "regs 0-15: SIM-PLC-202K setpoints 50 75 1200"})
    err = a._fabrication_gate("submit_finding", {
        "title": "[CTF] flag found",
        "evidence": "regs decode to FLAG{m0dbus_1s_4ll_4b0ut_r3g1573r5}",
    })
    assert err and "FABRICATION" in err


def test_real_flag_passes():
    a = _agent()
    a._ctf_flag_watch = True
    a._record_raw_result({"stdout": "GET /probe?token=FLAG{bgp_m0r3_sp3c1f1c_w1ns} HTTP/1.1"})
    err = a._fabrication_gate("submit_finding", {
        "title": "[CTF] flag found",
        "evidence": "FLAG{bgp_m0r3_sp3c1f1c_w1ns}",
    })
    assert err is None


def test_no_flag_in_finding_no_gate():
    a = _agent()
    a._ctf_flag_watch = True
    a._record_raw_result({"stdout": "some output"})
    err = a._fabrication_gate("submit_finding", {
        "title": "unauthorized read on plc",
        "evidence": "identity SIM-PLC-202K readable without auth",
    })
    assert err is None


def test_non_ctf_mode_no_gate():
    a = _agent()
    # 无 _ctf_flag_watch（普通渗透任务）→ 不拦
    err = a._fabrication_gate("submit_finding", {
        "evidence": "FLAG{whatever_never_seen}",
    })
    assert err is None


def test_other_tools_not_gated():
    a = _agent()
    a._ctf_flag_watch = True
    a._record_raw_result({"stdout": "x"})
    assert a._fabrication_gate("terminal", {"cmd": "echo FLAG{x1}"}) is None
    assert a._fabrication_gate("record_coverage", {"surface": "FLAG{x1}"}) is None


def test_no_raw_outputs_yet_passes():
    a = _agent()
    a._ctf_flag_watch = True
    # 还没任何工具输出（第一步就提交）→ 无从比对，放行
    assert a._fabrication_gate("submit_finding", {
        "evidence": "FLAG{first_call}",
    }) is None


def test_desc_exempt_flag_passes():
    """任务文本(desc)里出现的值豁免（那是给的情报，不算幻觉）。"""
    a = _agent()
    a._ctf_flag_watch = True
    a.messages = [{"role": "user",
                   "content": "objective ... token=FLAG{desc_given_value} ..."}]
    a._record_raw_result({"stdout": "unrelated"})
    err = a._fabrication_gate("submit_finding", {
        "evidence": "FLAG{desc_given_value}",
    })
    assert err is None


def test_register_dump_byte_sequence_passes():
    """agent 读到寄存器整数 [70,76,...]，在 LLM 里解成 flag 提交——字节序列在输出里，合法放行。"""
    from agents.executor import InhouseAgent
    a = _agent()
    a._ctf_flag_watch = True
    regs = [ord(c) for c in "FLAG{m0dbus_r3g1st3r_l34k}"]
    a._record_raw_result({"output": "registers: " + str(regs)})
    err = a._fabrication_gate("submit_finding", {
        "title": "[CTF] flag in regs",
        "evidence": "FLAG{m0dbus_r3g1st3r_l34k}",
    })
    assert err is None


def test_hallucinated_flag_not_in_register_dump_rejected():
    from agents.executor import InhouseAgent
    a = _agent()
    a._ctf_flag_watch = True
    # 实际读到的是 SIM-PLC-202K + setpoints（非 flag 字节）
    real = [ord(c) for c in "SIM-PLC-202K"] + [50, 75, 1200, 0, 1, 4, 20, 60, 100, 0]
    a._record_raw_result({"output": "regs: " + str(real)})
    err = a._fabrication_gate("submit_finding", {
        "evidence": "FLAG{m0dbus_1s_4ll_4b0ut_r3g1573r5}",
    })
    assert err and "FABRICATION" in err
