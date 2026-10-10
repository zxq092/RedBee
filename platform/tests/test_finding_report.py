from __future__ import annotations

import pytest

from pi_meta import board
from pi_meta import finding_report as fr
from pi_meta.model_runtime import (
    ChatResult,
    ModelRuntime,
    ResolvedRuntime,
    RuntimeResolution,
)

_TARGET = "http://target.test"


def post_finding(task_id: str, **kw):
    f = {"title": "SQLi in id", "vuln_class": "sqli", "location": "/vulns/sqli/?id=1",
         "poc": "id=1' OR '1'='1", "evidence": "uid=1, user=admin", "severity": "critical",
         **kw}
    return board.post(task_id, _TARGET, f, found_by="RedBee")


def fake_runtime():
    rt = ModelRuntime("m1", "http://x.test/v1", "K", 5, 2, "/v1/models", "v")
    return ResolvedRuntime(
        runtime=rt, candidate_runtimes=[rt], available_indices=[0], selected_index=0,
        degraded_from=None, degraded_chain=["m1"], runtime_id="rt-x",
        health_checked_at="2026-10-09T00:00:00+00:00", probe_status="healthy",
        probe_error_code=None)


# ---------------------------------------------------------------- reporter

def test_mechanical_report_preserves_poc_and_evidence():
    f = {"title": "SQLi", "severity": "critical", "vuln_class": "sqli",
         "location": "/x?id=1", "poc": "id=1' OR 1=1--", "evidence": "uid=1"}
    md = fr._mechanical_report(f, _TARGET)
    assert "id=1' OR 1=1--" in md
    assert "uid=1" in md
    assert "机械模板" in md
    assert "## 修复建议" not in md  # 机械模板不冒充 LLM 分析


def test_strip_code_fence():
    assert fr._strip_code_fence("```markdown\n## 概述\n正文\n```") == "## 概述\n正文"
    assert fr._strip_code_fence("## 概述\n正文") == "## 概述\n正文"


@pytest.mark.asyncio
async def test_write_finding_reports_llm_path(monkeypatch):
    fid = post_finding("t1")
    assert fid is not None
    calls = []

    class FakeClient:
        @staticmethod
        async def chat(resolved, payload):
            calls.append(payload)
            return ChatResult(True, "## 概述\n\n" + "SQL 注入漏洞详细分析" * 20,
                              [], "rt-x", [], None)

    async def fake_resolve():
        return RuntimeResolution(ok=True, runtime=fake_runtime(), error=None)

    monkeypatch.setattr(fr, "resolve_runtime", fake_resolve)
    monkeypatch.setattr(fr, "RuntimeClient", FakeClient)
    n = await fr.write_finding_reports("t1")
    assert n == 1
    f = board.get_finding("t1", fid)
    assert f["report_md"] and "SQL 注入漏洞详细分析" in f["report_md"]
    assert f["report_evidence_version"] == 1
    # 幂等：再跑一次不重写（无 stale）
    n2 = await fr.write_finding_reports("t1")
    assert n2 == 0
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_write_finding_reports_llm_failure_falls_back_mechanical(monkeypatch):
    fid = post_finding("t2")

    class FakeClient:
        @staticmethod
        async def chat(resolved, payload):
            return ChatResult(False, "", [], "rt-x", [],
                              None)

    async def fake_resolve():
        return RuntimeResolution(ok=True, runtime=fake_runtime(), error=None)

    monkeypatch.setattr(fr, "resolve_runtime", fake_resolve)
    monkeypatch.setattr(fr, "RuntimeClient", FakeClient)
    n = await fr.write_finding_reports("t2")
    assert n == 1
    f = board.get_finding("t2", fid)
    assert "机械模板" in f["report_md"]


@pytest.mark.asyncio
async def test_write_finding_reports_runtime_dead_goes_mechanical(monkeypatch):
    fid = post_finding("t3")

    async def fake_resolve():
        return RuntimeResolution(ok=False, runtime=None, error=None)

    monkeypatch.setattr(fr, "resolve_runtime", fake_resolve)
    n = await fr.write_finding_reports("t3")
    assert n == 1
    f = board.get_finding("t3", fid)
    assert "机械模板" in f["report_md"]


@pytest.mark.asyncio
async def test_evidence_update_bumps_version_and_triggers_rewrite(monkeypatch):
    fid = post_finding("t4")
    writes = []

    class FakeClient:
        @staticmethod
        async def chat(resolved, payload):
            writes.append(len(writes))
            return ChatResult(True, "## 概述\n\n" + f"报告版本{len(writes)}" * 20,
                              [], "rt-x", [], None)

    async def fake_resolve():
        return RuntimeResolution(ok=True, runtime=fake_runtime(), error=None)

    monkeypatch.setattr(fr, "resolve_runtime", fake_resolve)
    monkeypatch.setattr(fr, "RuntimeClient", FakeClient)
    assert await fr.write_finding_reports("t4") == 1
    # 同 dedup_key 再次贴板但 poc/evidence 有更新 → 版本 +1 → 报告重写
    again = board.post("t4", _TARGET, {
        "title": "SQLi in id", "vuln_class": "sqli", "location": "/vulns/sqli/?id=1",
        "poc": "id=1' UNION SELECT 1,2,3--", "evidence": "uid=1, user=admin, extra",
        "severity": "critical"}, found_by="RedBee")
    assert again is None  # 去重命中
    f = board.get_finding("t4", fid)
    assert f["evidence_version"] == 2
    assert f["report_evidence_version"] == 1  # 报告落后
    assert await fr.write_finding_reports("t4") == 1
    f = board.get_finding("t4", fid)
    assert f["report_evidence_version"] == 2
    assert len(writes) == 2


# ---------------------------------------------------------------- retester

def test_retest_prompt_focus_and_markers():
    f = {"title": "SQLi in id", "vuln_class": "sqli", "location": "/x?id=1",
         "poc": "id=1' OR 1=1--"}
    p = fr.retest_prompt(f)
    assert "复测任务" in p
    assert "id=1' OR 1=1--" in p
    assert "TARGET_UNREACHABLE" in p
    assert "不要探索其他漏洞" in p


def test_settle_retest_reproduced_confirms_original():
    fid = post_finding("t10")
    # 复测任务打出同 dedup_key finding
    assert post_finding("t11") is not None
    fr.record_retest(fid, "t11")
    n = fr.settle_retests("t11", "done")
    assert n == 1
    f = board.get_finding("t10", fid)
    assert f["status"] == "confirmed"
    assert f["confirmed_by"] == "retest:t11"
    assert f["retest_verdict"] == "reproduced"


def test_settle_retest_not_reproduced_keeps_status():
    fid = post_finding("t12")
    fr.record_retest(fid, "t13")  # 复测任务无任何 finding
    n = fr.settle_retests("t13", "done")
    assert n == 1
    f = board.get_finding("t12", fid)
    assert f["status"] == "found"  # 不自动判 false_positive
    assert f["retest_verdict"] == "not_reproduced"


def test_settle_retest_inconclusive_when_retest_task_died():
    fid = post_finding("t14")
    fr.record_retest(fid, "t15")
    fr.settle_retests("t15", "cancelled")
    f = board.get_finding("t14", fid)
    assert f["status"] == "found"
    assert f["retest_verdict"] == "inconclusive"


def test_settle_noop_for_non_retest_task():
    assert fr.settle_retests("t-nope", "done") == 0


def test_find_finding_any_task_and_missing():
    fid = post_finding("t16")
    f = fr.find_finding_any_task(fid)
    assert f is not None
    assert f["task_id"] == "t16"
    assert f["title"] == "SQLi in id"
    assert fr.find_finding_any_task(999999) is None
