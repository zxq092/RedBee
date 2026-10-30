# -*- coding: utf-8 -*-
"""分步执行模式（steps param）：参数校验 + 步骤文本构建。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pi_meta.real_dispatch import validate_task_params


def _setup_env(monkeypatch=None):
    """real_dispatch 导入 config.env——conftest 隔离由 fixture 承担（test_llm_breaker 前例）。"""


def test_steps_param_valid():
    ok, errs = validate_task_params({
        "steps": [
            {"name": "起中继", "prompt": "pkill -f ntlmrelayx; ...", "wait_s": 3},
            {"name": "种img", "prompt": "curl ... edit", "wait_s": 100},
            {"name": "读日志", "prompt": "cat /tmp/rl.log"},
        ]
    })
    assert not errs, errs
    assert len(ok["steps"]) == 3
    assert ok["steps"][1]["wait_s"] == 100
    assert ok["steps"][2]["wait_s"] == 0  # 缺省=0


def test_steps_param_rejects_garbage():
    # 非数组
    ok, errs = validate_task_params({"steps": "not-a-list"})
    assert "steps" not in ok and errs
    # 空
    ok, errs = validate_task_params({"steps": []})
    assert "steps" not in ok and errs
    # 缺 prompt
    ok, errs = validate_task_params({"steps": [{"name": "x"}]})
    assert "steps" not in ok and errs
    # wait_s 越界被夹紧
    ok, errs = validate_task_params({"steps": [{"name": "x", "prompt": "y", "wait_s": 99999}]})
    assert ok["steps"][0]["wait_s"] == 600


def test_steps_task_text_structure():
    from agents.orchestrator_v2 import _steps_task_text
    steps = [
        {"name": "s1", "prompt": "do alpha", "wait_s": 5},
        {"name": "s2", "prompt": "do beta", "wait_s": 0},
    ]
    t1 = _steps_task_text("BASE TASK", 0, steps, [])
    assert "BASE TASK" in t1
    assert "STEP 1/2" in t1 and "do alpha" in t1
    assert "前序步骤结果" not in t1
    t2 = _steps_task_text("BASE TASK", 1, steps, ["step1（s1）: 无新 finding"])
    assert "STEP 2/2" in t2 and "do beta" in t2
    assert "step1（s1）" in t2  # 步间上下文注入
    assert "不要尝试后续步骤" in t2


def test_nilgiri_adapter_passes_plan():
    import json
    from benchmark.adapters.nilgiri import NilgiriAdapter
    a = NilgiriAdapter()
    targets = {t["cid"]: t for t in a.list_targets()}
    # 只要有 plan 字段键存在（不依赖具体题）
    assert all("plan" in t for t in targets.values())
    m43 = targets.get("nilgiri-m4-s3-ntlm-relay")
    if m43 is not None:
        assert isinstance(m43.get("plan"), list)
