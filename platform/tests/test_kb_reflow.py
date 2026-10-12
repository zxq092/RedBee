"""regression: submit_finding 的 KB 回吐（_ingest_finding_to_kb）必须产 active 可检索条目。

旧 bug：source_type="agent"（不在 NEW_SOURCE_TYPES）→ ingest 强制 needs_review →
治理过滤挡掉、永远不可检索，且每次 submit 插垃圾行。修复后应 inhouse+candidate+verified → active。
"""
import pytest


@pytest.fixture
def iso_redkb(tmp_path, monkeypatch):
    from redkb import store
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "redkb_test.db"))


def test_ingest_finding_to_kb_produces_retrievable_active(iso_redkb):
    from agents.tools import _ingest_finding_to_kb
    from redkb import store, governance

    kb_id = _ingest_finding_to_kb(
        title="XPath injection in login user",
        poc="' or '1'='1", evidence="Login succeeded with injected query",
        asset="http://x/login", vuln_class="xpath", target_id="mutillidae")
    assert kb_id, "应返回 kb_id"

    # 治理状态 = active
    eid = kb_id
    conn = store._connect()
    try:
        from redkb.schemas import KnowledgeEntry
        row = conn.execute("SELECT * FROM knowledge WHERE id=?", (eid,)).fetchone()
        assert row is not None, "条目应已入库"
    finally:
        conn.close()
    # 可检索（list_knowledge 只返回 active）
    active = [e.id for e in store.list_knowledge()]
    assert kb_id in active, f"回吐条目应 active 可检索，实际不在 active 里: {active}"


def test_ingest_dedups_same_vuln_asset(iso_redkb):
    """同 vuln_class+asset(去标识) 不重复入库。"""
    from agents.tools import _ingest_finding_to_kb
    args = dict(title="sqli in user-info", poc="1' or '1'='1", evidence="union works",
                asset="http://x/user-info", vuln_class="sqli", target_id="dvwa")
    a = _ingest_finding_to_kb(**args)
    b = _ingest_finding_to_kb(**args)
    assert a == b, "重复 submit 应去重返回同一条，不再插新行"
