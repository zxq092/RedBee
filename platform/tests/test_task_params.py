"""每任务参数覆盖（POST /api/task 的 params 字段）：校验、合并、端到端传递。"""
import asyncio
from types import SimpleNamespace

import pytest


def test_validate_task_params_all_valid():
    from pi_meta.real_dispatch import validate_task_params
    out, errs = validate_task_params({
        "max_parallel": "3", "max_modules": 9, "child_max_turns": 80,
        "task_budget": 5400, "module_retry_delay": 0,
        "skip_recon": "true", "force_all_modules": 1,
    })
    assert errs == []
    assert out == {"max_parallel": 3, "max_modules": 9, "child_max_turns": 80,
                   "task_budget": 5400, "module_retry_delay": 0,
                   "skip_recon": True, "force_all_modules": True}


def test_validate_task_params_bad_values_dropped():
    from pi_meta.real_dispatch import validate_task_params
    out, errs = validate_task_params({"max_parallel": 99, "unknown_key": 1, "child_max_turns": "abc"})
    assert out == {}
    assert len(errs) == 3
    out, errs = validate_task_params("not-a-dict")
    assert out == {} and len(errs) == 1
    out, errs = validate_task_params(None)
    assert out == {} and errs == []


def test_validate_task_params_model(monkeypatch):
    from pi_meta.real_dispatch import validate_task_params
    # conftest 隔离了 .env，显式给定队列（与生产 .env 一致）
    monkeypatch.setenv("MODEL_PRIORITY", "qwen3.8-27b,DeepSeek-V4-Flash")
    # 队列内模型通过
    out, errs = validate_task_params({"model": "DeepSeek-V4-Flash"})
    assert out == {"model": "DeepSeek-V4-Flash"} and errs == []
    # 非法名称
    out, errs = validate_task_params({"model": "bad model name!"})
    assert out == {} and len(errs) == 1
    # 队列外模型拒绝
    out, errs = validate_task_params({"model": "gpt-9-not-configured"})
    assert out == {} and "不在已配置队列" in errs[0]


def test_merge_task_params():
    from pi_meta.real_dispatch import merge_task_params
    recipe = {"max_modules": 9, "force_all": True, "skip_recon": True,
              "max_parallel": 4, "child_max_turns": 80}
    m = merge_task_params(recipe, {"max_parallel": 2, "force_all_modules": False, "task_budget": 3600})
    assert m["max_parallel"] == 2
    assert m["force_all"] is False          # force_all_modules → force_all
    assert m["task_budget"] == 3600          # 新增键进配方
    assert m["max_modules"] == 9             # 未覆盖的配方值保留
    assert m["skip_recon"] is True
    # 原配方不被就地修改
    assert recipe["max_parallel"] == 4 and "task_budget" not in recipe
    assert merge_task_params(recipe, None) == recipe


@pytest.mark.asyncio
async def test_inhouse_run_threads_task_params_into_recipe(monkeypatch):
    """端到端：task_params 经 _inhouse_run 合并进 recipe 传给 OrchestratorV2.run。"""
    import agents.orchestrator_v2 as orch_mod
    import pi_meta.real_dispatch as rd

    captured = {}

    class FakeOrch:
        async def run(self, text, target, task_id="", runtime=None, modules=None,
                      progress_cb=None, target_id="", recipe=None):
            captured["recipe"] = recipe
            captured["modules"] = modules
            captured["text"] = text
            return {"ok": True, "findings": [], "assigned_modules": modules or []}

    monkeypatch.setattr(orch_mod, "OrchestratorV2", FakeOrch)
    monkeypatch.setattr(rd.planner, "modules_for", lambda *a, **kw: ["sqli", "xss"])
    # 未知靶场（无档案）→ resolve_recipe 返回 {}
    import pi_meta.target_profile as tp
    monkeypatch.setattr(tp, "target_profile_exists", lambda tid: False)

    rt = SimpleNamespace(runtime_id="rt-test", model="m")
    resolved = SimpleNamespace(runtime=rt, candidate_runtimes=[rt], available_indices=[0],
                               selected_index=0, degraded_from=None, degraded_chain=["m"],
                               runtime_id="rt-test", health_checked_at="", probe_status="unprobed",
                               probe_error_code=None)
    result = await rd._inhouse_run("attack", "http://10.0.0.1", resolved,
                                   task_id="t-test", target_id="unknown-x",
                                   task_params={"max_parallel": 1, "task_budget": 3000,
                                                "force_all_modules": False})
    assert result.ok
    recipe = captured["recipe"]
    assert recipe["max_parallel"] == 1
    assert recipe["task_budget"] == 3000
    assert recipe["force_all"] is False
    # 未知靶场 + 参数覆盖 → 不应追加"已知靶场"文案
    assert "KNOWN TARGET" not in captured["text"]


@pytest.mark.asyncio
async def test_inhouse_run_known_target_suffix_only_for_known(monkeypatch):
    import agents.orchestrator_v2 as orch_mod
    import pi_meta.real_dispatch as rd
    import pi_meta.target_profile as tp

    captured = {}

    class FakeOrch:
        async def run(self, text, target, task_id="", runtime=None, modules=None,
                      progress_cb=None, target_id="", recipe=None):
            captured["text"] = text
            captured["recipe"] = recipe
            return {"ok": True, "findings": [], "assigned_modules": modules or []}

    monkeypatch.setattr(orch_mod, "OrchestratorV2", FakeOrch)
    monkeypatch.setattr(rd.planner, "modules_for", lambda *a, **kw: ["sqli"])
    monkeypatch.setattr(tp, "target_profile_exists", lambda tid: True)
    monkeypatch.setattr(tp, "resolve_recipe", lambda tid: {
        "max_modules": 9, "force_all": True, "skip_recon": True,
        "max_parallel": 4, "child_max_turns": 80})

    rt = SimpleNamespace(runtime_id="rt-test", model="m")
    resolved = SimpleNamespace(runtime=rt, candidate_runtimes=[rt], available_indices=[0],
                               selected_index=0, degraded_from=None, degraded_chain=["m"],
                               runtime_id="rt-test", health_checked_at="", probe_status="unprobed",
                               probe_error_code=None)
    await rd._inhouse_run("attack", "http://10.0.0.1", resolved,
                          task_id="t-test", target_id="dvwa",
                          task_params={"max_parallel": 1})
    assert "KNOWN TARGET" in captured["text"]          # 已知靶场仍加防过度验证文案
    assert captured["recipe"]["max_parallel"] == 1      # 任务覆盖配方
    assert captured["recipe"]["skip_recon"] is True     # 配方其余项保留
