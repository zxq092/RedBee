"""regression: 撤回(revoked)后的条目必须不再可检索（治理判 non-active）。"""
import pytest
from redkb import governance, store
from redkb.schemas import KnowledgeEntry


@pytest.fixture
def iso_redkb(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "redkb_test.db"))


def _entry(**ov):
    v = {
        "id": "kb.r.1", "type": "poc", "title": "sqli poc",
        "content": "validated method", "tags": ["sqli"], "scope": "all",
        "source_type": "inhouse", "validation_status": "verified", "verified": False,
        "sanitization_status": "sanitized", "data_quality_status": "active",
        "status": "revoked",
        "redacted_content_hash": "h", "content_hash": "h",
    }
    v.update(ov)
    return v


def test_revoked_entry_governance_non_active(iso_redkb):
    entry = KnowledgeEntry.model_validate(_entry())
    assert governance.governance_status_for_entry(entry) == "revoked"
    assert governance.governance_allowed(entry) is False
    # 控制变量：同样字段但 status=verified → active（证明是 revoked 把它压成 non-active）
    entry2 = KnowledgeEntry.model_validate(_entry(status="verified", verified=True))
    assert governance.governance_allowed(entry2) is True
