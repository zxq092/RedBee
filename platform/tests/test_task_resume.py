"""Task checkpoint (task_state) + resume 计算/重派测试。

覆盖：
- save/get_task_state 持久化到临时库（隔离）
- get_task_state 对无记录返回 {}
- resume 端点：running 任务拒绝续跑 / unknown task 404 / 未完成模块计算
"""

import pytest
from fastapi.testclient import TestClient

from pi_meta import sessions
from agents import task_registry


@pytest.fixture(autouse=True)
def _iso(_isolate_pimeta_db, _isolate_agents_db):
    yield


@pytest.fixture
def api():
    from pi_meta import app as app_mod
    with TestClient(app_mod.app) as c:
        yield c


def test_task_state_roundtrip():
    st = {"planned": ["sqli", "xss"], "modules": {"sqli": "done_with_findings", "xss": "interrupted"}}
    sessions.save_task_state("t1", st)
    got = sessions.get_task_state("t1")
    assert got["planned"] == ["sqli", "xss"]
    assert got["modules"]["sqli"] == "done_with_findings"
    assert got["modules"]["xss"] == "interrupted"


def test_task_state_overwrite_and_unknown():
    sessions.save_task_state("t2", {"modules": {"m": "pending"}})
    sessions.save_task_state("t2", {"modules": {"m": "done_clean"}})
    assert sessions.get_task_state("t2")["modules"]["m"] == "done_clean"
    assert sessions.get_task_state("nonexistent") == {}


def test_unmark_cancelled():
    task_registry.mark_cancelled("t3")
    assert task_registry.is_cancelled("t3")
    task_registry.unmark_cancelled("t3")
    assert not task_registry.is_cancelled("t3")


def test_resume_unfinished_selection():
    st = {"modules": {"a": "done_clean", "b": "done_with_findings",
                      "c": "interrupted", "d": "pending"}}
    unfinished = [m for m, s in st["modules"].items()
                  if s in ("pending", "running", "interrupted")]
    assert sorted(unfinished) == ["c", "d"]


def test_resume_endpoint_rejects_running(api):
    """任务正在跑（_BG_TASKS 有未完成任务）→ resume 409。"""
    from pi_meta import app as app_mod
    class _FakeBg:
        def done(self):
            return False
    app_mod._BG_TASKS["t-running"] = _FakeBg()
    try:
        sessions.save_task_metadata("t-running", "t", "", "m", ["RedBee"], [], "running")
        r = api.post("/api/task/t-running/resume")
        assert r.status_code == 409
    finally:
        app_mod._BG_TASKS.pop("t-running", None)


def test_resume_endpoint_unknown(api):
    r = api.post("/api/task/no-such-task/resume")
    assert r.status_code == 404


def test_resume_dispatches_unfinished_as_list(api, monkeypatch):
    """resume 应只重派未完成模块，且以 list 形式传给 _run_real（与 validate_task_params 一致）。"""
    from pi_meta import app as app_mod
    captured = {}

    async def fake_run_real(agents, task, target, sid, task_id, tg, task_params=None,
                            *a, **kw):
        captured["task_params"] = task_params
        captured["task_id"] = task_id
        return []

    monkeypatch.setattr(app_mod, "_run_real", fake_run_real)
    # 准备一个被打断的任务
    sessions.save_task_metadata(
        "t-resume", "http://t", "t", "m", ["RedBee"], [], "interrupted",
        session_id="s1", task_text="task text", mode="pentest")
    sessions.save_task_state("t-resume", {"modules": {
        "sqli": "done_with_findings", "xss": "interrupted", "auth": "done_clean"}})

    r = api.post("/api/task/t-resume/resume")
    assert r.status_code == 200, r.text
    assert "xss" in (r.json().get("resume") or [])
    assert captured["task_params"]["modules"] == ["xss"]  # 只重派 unfinished，且是 list
    # 状态复位为 running
    meta = sessions.get_task_metadata("t-resume")
    assert meta["status"] == "running"


def test_continue_all_done_injects_context_and_reruns(api, monkeypatch, _iso):
    """continue：全 done 也能续打，且注入 ENGAGEMENT STATE 上下文（已确认的不重打）。"""
    from pi_meta import app as app_mod
    captured = {}

    async def fake_run_real(agents, task, target, sid, task_id, tg, task_params=None, *a, **kw):
        captured["task_text"] = task
        captured["task_params"] = task_params
        return []

    monkeypatch.setattr(app_mod, "_run_real", fake_run_real)
    sessions.save_task_metadata(
        "t-cont", "http://t", "t", "m", ["RedBee"], [], "done",
        session_id="s-cont", task_text="original task", mode="pentest")
    # 全 done（无未完成模块）
    sessions.save_task_state("t-cont", {"modules": {
        "sqli": "done_with_findings", "xss": "done_clean", "xxe": "interrupted"}})

    r = api.post("/api/task/t-cont/continue")
    assert r.status_code == 200, r.text
    # xxe 未完成 → 续打；但 continue 还会带上下文
    assert "xxe" in (r.json().get("continue") or [])
    assert "ENGAGEMENT STATE" in captured["task_text"]
    assert captured["task_params"]["modules"] == ["xxe"]


def test_continue_with_explicit_modules(api, monkeypatch, _iso):
    """continue body.modules → 指定方向覆盖默认。"""
    from pi_meta import app as app_mod
    captured = {}

    async def fake_run_real(agents, task, target, sid, task_id, tg, task_params=None, *a, **kw):
        captured["task_params"] = task_params
        captured["task_text"] = task
        return []

    monkeypatch.setattr(app_mod, "_run_real", fake_run_real)
    sessions.save_task_metadata(
        "t-cont2", "http://t", "t", "m", ["RedBee"], [], "done",
        session_id="s-cont2", task_text="orig", mode="pentest")
    sessions.save_task_state("t-cont2", {"modules": {"sqli": "done_clean"}})
    r = api.post("/api/task/t-cont2/continue", json={"modules": "xxe,lfi", "intent": "补 XXE/LFI"})
    assert r.status_code == 200, r.text
    assert captured["task_params"]["modules"] == ["xxe", "lfi"]
    assert "补 XXE/LFI" in captured["task_text"]
    assert "ENGAGEMENT STATE" in captured["task_text"]


def test_continue_running_rejected(api, monkeypatch, _iso):
    from pi_meta import app as app_mod
    class _FakeBg:
        def done(self):
            return False
    app_mod._BG_TASKS["t-crun"] = _FakeBg()
    try:
        sessions.save_task_metadata("t-crun", "t", "", "m", ["RedBee"], [], "running")
        r = api.post("/api/task/t-crun/continue")
        assert r.status_code == 409
    finally:
        app_mod._BG_TASKS.pop("t-crun", None)
