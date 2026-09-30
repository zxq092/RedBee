"""CTF/目标猎取模式（mode=ctf）：模式判定、参数校验、编排分支、flag 早停、skill 注入。

设计: docs/CTF目标猎取模式-设计.md。xben-002 实测校准（单猎手聚焦+档案热启动 21min 命中）。
"""
import asyncio
import sqlite3

import pytest


# ---------- resolve_mode（判定顺序：显式 > 文本信号 > 档案 kind；PIMETA_CTF_AUTO 回滚开关）----------

def test_resolve_mode_explicit_wins():
    from pi_meta.target_profile import resolve_mode
    assert resolve_mode("take the flag", "", "ctf") == ("ctf", "explicit")
    # 显式 pentest 压制文本信号（"对 CTF 靶机做常规渗透"逃生门）
    assert resolve_mode("take the flag", "", "pentest") == ("pentest", "explicit")


def test_resolve_mode_task_text_signals():
    from pi_meta.target_profile import resolve_mode
    assert resolve_mode("唯一目标是找到并取出隐藏的 flag", "") == ("ctf", "task-text")
    assert resolve_mode("找到 FLAG{abc} 即胜利", "") == ("ctf", "task-text")
    assert resolve_mode("Take the flag in the app", "") == ("ctf", "task-text")
    assert resolve_mode("拿到通关 flag 就算赢", "") == ("ctf", "task-text")
    # 防误报：出现 CTF 但无目标性词 → 普通渗透
    assert resolve_mode("渗透测试这个 CTF 平台的登录接口 SQL 注入", "") == ("pentest", "default")
    assert resolve_mode("扫描 dvwa 的 sqli 和 xss", "") == ("pentest", "default")


def test_resolve_mode_profile_kind(tmp_path, monkeypatch):
    import agents.orchestrator_v2 as ov2
    import pi_meta.target_profile as tp
    from pi_meta.target_profile import resolve_mode
    monkeypatch.setattr(ov2, "TARGETS_DIR", str(tmp_path))
    monkeypatch.setattr(tp, "TARGETS_DIR", str(tmp_path))
    (tmp_path / "xben-test.md").write_text("# 靶场档案\n- kind: ctf\n", encoding="utf-8")
    (tmp_path / "dvwa.md").write_text("# 靶场档案（无 kind）\n", encoding="utf-8")
    # 无目标词的任务文本 + 档案 kind: ctf → 自动 CTF（v2 场景：用户只说"打 xben"）
    assert resolve_mode("打这个靶场", "xben-test") == ("ctf", "target-profile")
    assert resolve_mode("打这个靶场", "dvwa") == ("pentest", "default")


def test_mark_profile_ctf_idempotent(tmp_path, monkeypatch):
    import agents.orchestrator_v2 as ov2
    import pi_meta.target_profile as tp
    monkeypatch.setattr(ov2, "TARGETS_DIR", str(tmp_path))
    monkeypatch.setattr(tp, "TARGETS_DIR", str(tmp_path))
    (tmp_path / "t.md").write_text("# 靶场档案\n", encoding="utf-8")
    assert tp.mark_profile_ctf("t") is True
    assert tp.profile_is_ctf("t") is True
    # 幂等：已标不重复写
    txt = (tmp_path / "t.md").read_text(encoding="utf-8")
    assert tp.mark_profile_ctf("t") is False
    assert (tmp_path / "t.md").read_text(encoding="utf-8") == txt
    # 无档案不写
    assert tp.mark_profile_ctf("missing") is False
    # 标记后可被 resolve_mode 的 target-profile 信号识别
    assert tp.resolve_mode("打这个靶场", "t") == ("ctf", "target-profile")


def test_resolve_mode_auto_disabled(monkeypatch):
    import pi_meta.target_profile as tp
    from pi_meta.target_profile import resolve_mode
    monkeypatch.setattr(tp, "cfg_env", lambda key, default="": "0")
    assert resolve_mode("找到 flag 通关", "") == ("pentest", "default")
    # 显式仍有效（回滚只关自动判定）
    assert resolve_mode("随便什么", "", "ctf") == ("ctf", "explicit")


# ---------- validate_task_params（mode 枚举校验）----------

def test_validate_mode_param():
    from pi_meta.real_dispatch import validate_task_params
    out, errs = validate_task_params({"mode": "ctf"})
    assert out == {"mode": "ctf"} and errs == []
    out, errs = validate_task_params({"mode": "CTF"})
    assert out == {"mode": "ctf"} and errs == []
    out, errs = validate_task_params({"mode": "bogus"})
    assert out == {} and len(errs) == 1


# ---------- 临时 pimeta.db（findings/coverage 表）----------

@pytest.fixture()
def pimeta_db(tmp_path, monkeypatch):
    import agents.tools as tools
    db = tmp_path / "pimeta.db"
    monkeypatch.setattr(tools, "DB_PATH", str(db))
    tools._ensure_schema()
    return db


def _insert_finding(task_id, title, evidence, poc=""):
    import agents.tools as tools
    conn = sqlite3.connect(str(tools.DB_PATH))
    conn.execute(
        "INSERT INTO findings (task_id, target, title, vuln_class, poc, evidence, severity, status) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (task_id, "http://t", title, "idor", poc, evidence, "high", "found"))
    conn.commit()
    conn.close()


# ---------- _flag_hit（早停判据：只认 flag 模式的新 finding，旁证不触发）----------

def test_flag_hit_requires_flag_pattern(pimeta_db):
    from agents.orchestrator_v2 import _flag_hit, _finding_ids
    before = _finding_ids("t1")
    _insert_finding("t1", "Default Credentials (test:test)", "login works with test:test")
    assert _flag_hit("t1", before) is None  # 旁证 finding 不触发（R1 假成功教训）
    _insert_finding("t1", "IDOR leaks FLAG",
                    "FLAG{7ef0f69d288b3bb79dd210f4b4bc3b26a1d8c3d615294a2ee6cc3a81c2c5b7fa}")
    hit = _flag_hit("t1", before)
    assert hit is not None and "IDOR" in hit["title"]


def test_flag_hit_ignores_preexisting(pimeta_db):
    from agents.orchestrator_v2 import _flag_hit, _finding_ids
    _insert_finding("t1", "old flag finding", "FLAG{old}")
    before = _finding_ids("t1")
    _insert_finding("t1", "new non-flag", "some evidence")
    assert _flag_hit("t1", before) is None


def test_flag_pattern_env_override(monkeypatch, pimeta_db):
    # 直接 patch orchestrator 绑定的 cfg_env（不依赖 import 顺序/ .env 重载行为）
    import agents.orchestrator_v2 as ov2
    monkeypatch.setattr(ov2, "cfg_env",
                        lambda key, default="": r"SECRET_\w+" if key == "PIMETA_CTF_FLAG_PATTERN" else default)
    from agents.orchestrator_v2 import _flag_hit, _finding_ids
    before = _finding_ids("t2")
    _insert_finding("t2", "secret leaked", "SECRET_ABC123 in response")
    assert _flag_hit("t2", before) is not None
    assert _flag_hit("t3", _finding_ids("t3")) is None  # 无 finding 的任务


# ---------- run() ctf 分支：单 objective 猎手 + stop_check 透传 + 关 gap ----------

def _async_const(value):
    async def _f(*a, **kw):
        return value
    return _f


@pytest.mark.asyncio
async def test_run_ctf_dispatches_single_objective(pimeta_db, monkeypatch):
    import agents.orchestrator_v2 as ov2
    from types import SimpleNamespace
    captured = {"modules": []}

    async def fake_run_child(module, target, task, task_id, intel_block, runtime,
                             progress_cb=None, child_max_turns=40, shared_container="",
                             task_budget=0, stop_check=None):
        captured["modules"].append(module)
        captured["stop_check"] = stop_check
        return ov2._ChildResult(module, [], error="")

    monkeypatch.setattr(ov2, "_run_child", fake_run_child)
    monkeypatch.setattr(ov2, "_task_container_ensure", _async_const(""))
    monkeypatch.setattr(ov2, "_task_container_kill", _async_const(None))
    monkeypatch.setattr(ov2, "store_inhouse_case", lambda *a, **kw: "case-test")

    rt = SimpleNamespace(runtime_id="rt-test", model="m")
    orch = ov2.OrchestratorV2()
    result = await orch.run("找到 flag", "http://10.0.0.99", task_id="t-ctf-1", runtime=rt,
                            target_id="", recipe={"mode": "ctf", "skip_recon": True,
                                                  "max_parallel": 2, "child_max_turns": 10})
    assert captured["modules"] == ["objective"]      # 单猎手，无类 fan-out
    assert captured["stop_check"] is not None        # 早停判据已挂
    assert result["mode"] == "ctf"
    assert result["objective_met"] is False          # 无 flag finding → unmet
    rd = [p for p in result["phases"] if p.get("phase") == "root-decide"]
    assert rd and rd[0].get("reason") == "ctf-objective-hunt"


@pytest.mark.asyncio
async def test_run_pentest_unchanged_no_stop_check(pimeta_db, monkeypatch):
    import agents.orchestrator_v2 as ov2
    from types import SimpleNamespace
    captured = {"modules": []}

    async def fake_run_child(module, target, task, task_id, intel_block, runtime,
                             progress_cb=None, child_max_turns=40, shared_container="",
                             task_budget=0, stop_check=None):
        captured["modules"].append(module)
        captured["stop_check"] = stop_check
        return ov2._ChildResult(module, [], error="")

    monkeypatch.setattr(ov2, "_run_child", fake_run_child)
    monkeypatch.setattr(ov2, "_task_container_ensure", _async_const(""))
    monkeypatch.setattr(ov2, "_task_container_kill", _async_const(None))
    monkeypatch.setattr(ov2, "store_inhouse_case", lambda *a, **kw: "case-test")
    monkeypatch.setattr(ov2, "_root_plan", _async_const(
        {"ok": True, "modules": ["sqli"], "stop": False, "reason": "test"}))

    rt = SimpleNamespace(runtime_id="rt-test", model="m")
    orch = ov2.OrchestratorV2()
    result = await orch.run("打 sqli", "http://10.0.0.99", task_id="t-pt-1", runtime=rt,
                            target_id="", recipe={"skip_recon": True, "max_parallel": 2,
                                                  "child_max_turns": 10})
    assert captured["modules"] == ["sqli"]           # 渗透路径行为零变化
    assert captured["stop_check"] is None
    assert result["mode"] == "pentest"
    assert result["objective_met"] is False


@pytest.mark.asyncio
async def test_run_ctf_objective_met_via_flag_finding(pimeta_db, monkeypatch):
    """CTF 早停端到端：fake child 在 stop_check 前贴一条 flag finding → objective_met。"""
    import agents.orchestrator_v2 as ov2
    from types import SimpleNamespace

    async def fake_run_child(module, target, task, task_id, intel_block, runtime,
                             progress_cb=None, child_max_turns=40, shared_container="",
                             task_budget=0, stop_check=None):
        _insert_finding(task_id, "IDOR receipt leaks flag",
                        "FLAG{deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef}")
        assert stop_check() is not None              # 贴板后判据即命中
        return ov2._ChildResult(module, [], error="")

    monkeypatch.setattr(ov2, "_run_child", fake_run_child)
    monkeypatch.setattr(ov2, "_task_container_ensure", _async_const(""))
    monkeypatch.setattr(ov2, "_task_container_kill", _async_const(None))
    monkeypatch.setattr(ov2, "store_inhouse_case", lambda *a, **kw: "case-test")

    rt = SimpleNamespace(runtime_id="rt-test", model="m")
    orch = ov2.OrchestratorV2()
    result = await orch.run("找到 flag", "http://10.0.0.99", task_id="t-ctf-2", runtime=rt,
                            target_id="", recipe={"mode": "ctf", "skip_recon": True,
                                                  "child_max_turns": 10})
    assert result["objective_met"] is True
    # objective 事件走 emit→task_logs（不进 phases 列表），以 result 字段为准


# ---------- skill 注入：objective → ctf-hunt ----------

def test_objective_module_loads_ctf_hunt_skill():
    from agents.tools import get_skill_content
    content = get_skill_content("objective")
    assert content and "anomaly" in content.lower() or "flag" in content.lower()
    assert "sql injection specialist" not in content.lower()


def test_ctf_hunt_skill_in_registry():
    from agents.tools import _SKILLS_PATH
    assert "ctf-hunt" in _SKILLS_PATH
