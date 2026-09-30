from __future__ import annotations

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from redkb import governance, store
from redkb.app import app
from redkb.case_schema import CaseReview, CaseSnapshot, case_id_for
from redkb.schemas import Candidate, EvidenceRef, KnowledgeEntry, PromoteRequest


def hash_text(value: str) -> str:
    return governance.hash_text(value)


def candidate_entry(**overrides):
    values = {
        "id": "kb.test.1",
        "type": "attack_primitive",
        "title": "Bounded SQL injection validation",
        "content": "Validate a parameter with a controlled request and compare the response.",
        "tags": ["webapp", "sqli"],
        "scope": "all",
        "status": "candidate",
        "verified": False,
        "source_type": "pentagi",
        "source_id": "flow-1",
        "source_flow": "flow-1",
        "case_id": case_id_for("pentagi", "flow-1"),
        "redacted_content_hash": hash_text("validated method content"),
        "content_hash": hash_text("validated method content"),
        "actual_tool": "sqlmap",
        "validation_status": "candidate",
        "sanitization_status": "sanitized",
        "data_quality_status": "active",
        "case_evidence": [EvidenceRef(evidence_id="ev-1", evidence_hash=hash_text("evidence"))],
        "version": 1,
    }
    values.update(overrides)
    return KnowledgeEntry(**values)


def test_case_identity_and_source_constraints():
    assert case_id_for("pentagi", "flow-1") == case_id_for("pentagi", "flow-1")
    assert case_id_for("pentagi", "flow-1").startswith("case-")

    snapshot = CaseSnapshot(
        schema_version=1,
        source_type="pentagi",
        source_id="flow-1",
        source_flow="flow-1",
        agent="agent",
        model="model",
        runtime_id="runtime-1",
        task="task",
        target="http://192.168.71.19",
        target_id="dvwa",
        modules=["sqli"],
        trajectory={"tool_calls": [], "llm_turns": {"count": 0}, "raw_evidence_ref": []},
        provenance={"captured_at": "2026-09-17T00:00:00+00:00", "adapter_version": "test", "raw_size_bytes": 1, "sanitized": True},
    )
    assert snapshot.case_id == case_id_for("pentagi", "flow-1")
    with pytest.raises(Exception):
        CaseSnapshot(
            schema_version=1,
            source_type="inhouse",
            source_id="task-1",
            source_flow="flow-1",
            agent="agent",
            model="model",
            runtime_id="runtime-1",
            task="task",
            target="target",
            target_id="target-1",
            trajectory={"tool_calls": [], "llm_turns": {"count": 0}, "raw_evidence_ref": []},
            provenance={"captured_at": "now", "adapter_version": "test", "raw_size_bytes": 1, "sanitized": True},
        )


def test_legacy_source_normalization_and_sanitization_vectors():
    assert governance.normalize_source_type("llm-expert") == "legacy"
    assert governance.normalize_source_type("agent-distillation") == "legacy"

    clean = governance.sanitize_text("Use a controlled request to compare responses.")
    assert clean.sanitized is True
    assert clean.status == "sanitized"

    sensitive = governance.sanitize_text("cookie=abc; Authorization: Bearer token; md5=0123456789abcdef; http://192.168.71.19")
    assert sensitive.sanitized is False
    assert sensitive.status in {"needs_review", "quarantined"}
    assert "abc" not in sensitive.content
    assert "token" not in sensitive.content
    assert "192.168.71.19" not in sensitive.content

    query = governance.sanitize_text("curl -s http://localhost:8001/kb/query -d '{\"query\":\"x\"}'")
    assert query.status == "quarantined"
    assert "kb/query" not in query.content


def test_migration_adds_governance_versions_and_normalizes_legacy_rows(tmp_path, monkeypatch):
    db_path = tmp_path / "redkb.db"
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(db_path))
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE knowledge (id TEXT PRIMARY KEY, type TEXT, title TEXT, content TEXT, tags TEXT, scope TEXT, status TEXT, verified INTEGER, proof_method TEXT, source_type TEXT, case_evidence TEXT, source_evidence TEXT, proved_at TEXT, proof_evidence TEXT, preconditions TEXT, cve_id TEXT, affected TEXT, version TEXT, cvss REAL, poc_ref TEXT, usage_count INTEGER, success_rate REAL, last_used TEXT, disabled INTEGER, coverage_state TEXT, confidence REAL, created_at TEXT, updated_at TEXT, vect BLOB)")
    conn.execute("INSERT INTO knowledge VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
        "old-1", "guide", "Old", "content", "[]", "all", "authoritative", 1, "human", "llm-expert", "[]", None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
    ))
    conn.commit()
    conn.close()

    store._connect().close()
    conn = sqlite3.connect(db_path)
    assert conn.execute("PRAGMA table_info(knowledge)").fetchone()[1] == "id"
    assert {r[1] for r in conn.execute("PRAGMA table_info(knowledge)")}.issuperset({
        "source_id", "source_flow", "case_id", "legacy_source", "redacted_content_hash",
        "validation_status", "sanitization_status", "data_quality_status", "version",
    })
    assert conn.execute("SELECT source_type, legacy_source, status FROM knowledge WHERE id='old-1'").fetchone() == ("legacy", "llm-expert", "needs_review")
    assert conn.execute("SELECT status FROM redkb_governance WHERE knowledge_id='old-1'").fetchone()[0] == "reviewing"
    assert conn.execute("SELECT COUNT(*) FROM knowledge_versions WHERE knowledge_id='old-1'").fetchone()[0] == 1
    conn.close()


def test_ingest_is_versioned_and_governance_filtered(tmp_path, monkeypatch):
    db_path = tmp_path / "redkb.db"
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(db_path))

    first = candidate_entry()
    first.content = "first content"
    first.content_redacted = "first content"
    first.redacted_content_hash = hash_text("first content")
    first.content_hash = first.redacted_content_hash
    first.case_evidence = [EvidenceRef(evidence_id="ev-1", evidence_hash=hash_text("first evidence"))]
    first.validation_status = "verified"
    first.verified = True
    first.proof_method = "system"
    first.status = "candidate"
    first.data_quality_status = "active"
    first.sanitization_status = "sanitized"
    first.source_type = "pentagi"
    first.source_id = "flow-1"
    first.source_flow = "flow-1"
    first.case_id = case_id_for("pentagi", "flow-1")
    first.version = 1

    assert store.ingest(first) == "kb.test.1"
    assert store.ingest(first) == "kb.test.1"
    second = candidate_entry()
    second.content = "second content"
    second.content_redacted = "second content"
    second.redacted_content_hash = hash_text("second content")
    second.content_hash = second.redacted_content_hash
    second.case_evidence = [EvidenceRef(evidence_id="ev-2", evidence_hash=hash_text("second evidence"))]
    second.validation_status = "verified"
    second.verified = True
    second.status = "candidate"
    second.data_quality_status = "active"
    second.sanitization_status = "sanitized"
    second.version = 1
    assert store.ingest(second) == "kb.test.1"

    conn = sqlite3.connect(db_path)
    assert int(conn.execute("SELECT version FROM knowledge WHERE id='kb.test.1'").fetchone()[0]) == 1
    assert conn.execute("SELECT COUNT(*) FROM knowledge_versions WHERE knowledge_id='kb.test.1'").fetchone()[0] == 2
    conn.close()

    assert [e.id for e in store.query("first content", include_candidates=True)] == ["kb.test.1"]
    assert store.get_knowledge("kb.test.1") is not None
    assert [e.id for e in store.list_knowledge()] == ["kb.test.1"]


def test_candidate_validation_fail_closed_and_requires_restricted_evidence():
    case = CaseSnapshot(
        schema_version=1,
        source_type="pentagi",
        source_id="flow-1",
        source_flow="flow-1",
        agent="agent",
        model="model",
        runtime_id="runtime-1",
        task="task",
        target="http://192.168.71.19",
        target_id="dvwa",
        modules=["sqli"],
        trajectory={"tool_calls": [], "llm_turns": {"count": 0}, "raw_evidence_ref": []},
        provenance={"captured_at": "now", "adapter_version": "test", "raw_size_bytes": 1, "sanitized": True},
    )
    evidence = {"evidence_id": "ev-1", "evidence_hash": hash_text("success response 200"), "content": "success response 200"}
    valid = Candidate(
        source_type="pentagi",
        source_id="flow-1",
        source_flow="flow-1",
        case_id=case_id_for("pentagi", "flow-1"),
        entity_id=governance.deterministic_entity_id(case_id_for("pentagi", "flow-1"), "candidate", hash_text("compare controlled responses")),
        entity_type="candidate",
        title="Bounded SQL injection validation",
        technique="sqli",
        content_redacted="compare controlled responses",
        content_hash=hash_text("compare controlled responses"),
        actual_tool="sqlmap",
        evidence_id="ev-1",
        evidence_redacted="success response 200",
        evidence_hash=hash_text("success response 200"),
        validation_status="candidate",
        sanitization_status="sanitized",
        created_at="2026-09-17T00:00:00+00:00",
        adapter_version="test",
    )
    result = governance.validate_candidate(valid, case, evidence)
    assert result.status == "validated"

    missing = valid.model_copy(update={"evidence_hash": hash_text("wrong")})
    assert governance.validate_candidate(missing, case, evidence).status == "quarantined"
    query_tool = valid.model_copy(update={"actual_tool": "kb_query"})
    assert governance.validate_candidate(query_tool, case, evidence).status == "quarantined"
    assert governance.validate_candidate(valid, case, {}).status == "quarantined"


def test_promote_rejects_bad_identity_hash_and_actor_then_retracts(tmp_path, monkeypatch):
    db_path = tmp_path / "redkb.db"
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(db_path))
    entry = candidate_entry()
    entry.content = "verified content"
    entry.content_redacted = "verified content"
    entry.redacted_content_hash = hash_text("verified content")
    entry.content_hash = entry.redacted_content_hash
    entry.case_evidence = [EvidenceRef(evidence_id="ev-1", evidence_hash=hash_text("verified evidence"))]
    entry.validation_status = "verified"
    entry.verified = True
    entry.status = "candidate"
    entry.proof_method = "system"
    entry.data_quality_status = "active"
    entry.sanitization_status = "sanitized"
    entry.version = 1
    store.ingest(entry)

    req = PromoteRequest(
        source_type="pentagi",
        source_id="flow-1",
        source_flow="flow-1",
        case_id=case_id_for("pentagi", "flow-1"),
        entity_id="entity-1",
        content_hash=entry.redacted_content_hash,
        proof_method="system",
        verified=True,
        case_evidence=[EvidenceRef(evidence_id="ev-1", evidence_hash=hash_text("verified evidence"))],
    )
    promoted = store.promote("kb.test.1", req, actor="auto_ingest")
    assert promoted.status == "authoritative"
    assert promoted.verified is True

    bad_source = req.model_copy(update={"source_type": "inhouse"})
    with pytest.raises(store.GovernanceError) as exc:
        store.promote("kb.test.1", bad_source, actor="auto_ingest")
    assert exc.value.status_code == 403

    bad_hash = req.model_copy(update={"content_hash": "0" * 64})
    with pytest.raises(store.GovernanceError) as exc:
        store.promote("kb.test.1", bad_hash, actor="auto_ingest")
    assert exc.value.status_code == 409

    with pytest.raises(store.GovernanceError) as exc:
        store.promote("kb.test.1", req, actor="unknown")
    assert exc.value.status_code == 403

    retraced = store.retract("kb.test.1", actor="auto_ingest", reason_code="retired")
    assert retraced.status == "revoked"
    assert retraced.verified is False


def test_api_actor_gates_and_governance_projection(tmp_path, monkeypatch):
    db_path = tmp_path / "redkb.db"
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(db_path))
    monkeypatch.setenv("REDKB_ADMIN_TOKEN", "admin-secret")

    client = TestClient(app)
    entry = candidate_entry()
    entry.content = "api content"
    entry.content_redacted = "api content"
    entry.redacted_content_hash = hash_text("api content")
    entry.content_hash = entry.redacted_content_hash
    entry.case_evidence = [EvidenceRef(evidence_id="ev-api", evidence_hash=hash_text("api evidence"))]
    entry.validation_status = "verified"
    entry.verified = True
    entry.status = "candidate"
    entry.data_quality_status = "active"
    entry.sanitization_status = "sanitized"
    entry.version = 1
    assert client.post("/kb/ingest", json=entry.model_dump()).status_code == 403
    assert client.post("/kb/ingest", headers={"X-Service-Actor": "auto_ingest"}, json=entry.model_dump()).status_code == 200

    promoted = client.post("/kb/promote/kb.test.1", headers={"X-Service-Actor": "auto_ingest"}, json={
        "source_type": "pentagi", "source_id": "flow-1", "source_flow": "flow-1",
        "case_id": case_id_for("pentagi", "flow-1"), "entity_id": "entity-api",
        "content_hash": entry.redacted_content_hash, "proof_method": "system", "verified": True,
        "case_evidence": [{"evidence_id": "ev-api", "evidence_hash": hash_text("api evidence")}],
    })
    assert promoted.status_code == 200
    assert client.get("/kb/kb.test.1").json()["id"] == "kb.test.1"
    assert "ev-api" not in json.dumps(client.get("/kb/kb.test.1").json())

    quarantine = KnowledgeEntry(
        id="kb.quarantine", type="guide", title="Quarantine", content="curl /kb/query",
        scope="all", status="candidate", source_type="pentagi", source_id="flow-q",
        case_id=case_id_for("pentagi", "flow-q"), redacted_content_hash=hash_text("quarantine"),
        content_hash=hash_text("quarantine"), actual_tool="kb_query", validation_status="candidate",
        sanitization_status="quarantined", data_quality_status="quarantined",
    )
    assert client.post("/kb/ingest", headers={"X-Actor": "admin", "Authorization": "Bearer admin-secret"}, json=quarantine.model_dump()).status_code == 200
    assert client.get("/kb/kb.quarantine").status_code == 404
    audit = client.get("/kb/governance/kb.quarantine", headers={"Authorization": "Bearer admin-secret"})
    assert audit.status_code == 200
    assert audit.json()["status"] == "quarantined"


def test_inhouse_case_snapshot_persists_snapshot_and_restricted_evidence(tmp_path, monkeypatch):
    db_path = tmp_path / "redkb.db"
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(db_path))

    from agents.executor import build_inhouse_case_snapshot

    snapshot = build_inhouse_case_snapshot(
        task_id="task-1",
        target="http://target.test",
        target_id="target-1",
        model="model-1",
        runtime_id="runtime-1",
        findings=[{"id": 7, "status": "found", "severity": "medium", "dedup_key": "sqli@id"}],
        coverage=[{"id": 2, "surface": "http://target.test/login", "risk_area": "sqli", "outcome": "reported", "evidence": "success response 200"}],
        tool_calls=[{"name": "sqlmap", "status": "ok", "args": "url=http://target.test/login?id=1", "result": "injectable_params=[id]"}],
        llm_turns=3,
    )

    assert snapshot.source_type == "inhouse"
    assert snapshot.source_id == "task-1"
    assert snapshot.source_flow is None
    assert snapshot.case_id == case_id_for("inhouse", "task-1")
    assert snapshot.trajectory.llm_turns == {"count": 3}

    cid = store.submit_case(snapshot)
    persisted = store.get_case_snapshot(cid)
    assert persisted["source_id"] == "task-1"
    assert persisted["findings"][0]["id"] == 7
    assert persisted["trajectory"]["tool_calls"][0]["name"] == "sqlmap"

    evidence_id = "ev-inhouse-1"
    evidence_hash = hash_text("success response 200")
    store.add_case_evidence(cid, evidence_id, "success response 200", kind="finding")
    restricted = store.get_restricted_evidence(evidence_id, actor="auto_ingest")
    assert restricted["evidence_id"] == evidence_id
    assert restricted["evidence_hash"] == evidence_hash


def test_inhouse_candidate_promotion_uses_valid_governance_contract(tmp_path, monkeypatch):
    db_path = tmp_path / "redkb.db"
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(db_path))

    from auto_ingest import distill_inhouse_case, promote_inhouse_candidate
    from agents.executor import build_inhouse_case_snapshot

    case = build_inhouse_case_snapshot(
        task_id="task-1",
        target="http://target.test",
        target_id="target-1",
        model="model-1",
        runtime_id="runtime-1",
        findings=[],
        coverage=[{"id": 1, "surface": "http://target.test/login", "risk_area": "sqli", "outcome": "reported", "evidence": "success response 200"}],
        tool_calls=[],
        llm_turns=1,
    )
    case_id = store.submit_case(case)
    evidence_id = "ev-inhouse-2"
    evidence_hash = hash_text("success response 200")
    store.add_case_evidence(case.case_id, evidence_id, "success response 200", kind="finding")

    candidate = distill_inhouse_case(case, evidence_id=evidence_id, evidence_hash=evidence_hash)
    assert candidate.source_type == "inhouse"
    assert candidate.source_id == "task-1"
    assert candidate.case_id == case.case_id
    assert candidate.actual_tool == "sqlmap"
    assert candidate.evidence_id == evidence_id

    promoted = promote_inhouse_candidate(candidate)
    assert promoted is not None
    # 当前契约：distill 只把经验沉淀为 candidate 状态（verified 由后续任务确认后提升），
    # 不自动升 authoritative——见 auto_ingest.promote_inhouse_candidate 的 docstring
    assert promoted.status == "candidate"
    assert promoted.validation_status == "candidate"


def _inhouse_entry(content: str, case_id: str, source_id: str, ev_id: str):
    return KnowledgeEntry(
        id=None, type="attack_primitive", title="t validation technique",
        content=content, content_redacted=content,
        tags=["auto-distilled", "inhouse"], scope="all", status="candidate",
        verified=False, source_type="inhouse", source_id=source_id, source_flow=None,
        case_id=case_id, distilled_from=case_id,
        redacted_content_hash=hash_text(content), content_hash=hash_text(content),
        actual_tool="http_request", validation_status="candidate",
        sanitization_status="sanitized", data_quality_status="active",
        case_evidence=[EvidenceRef(evidence_id=ev_id, evidence_hash=hash_text("ev"))],
        provenance={"case_id": case_id, "source_task": source_id},
    )


def test_ingest_content_hash_dedup_keeps_single_row_and_latest_case(tmp_path, monkeypatch):
    db_path = tmp_path / "redkb.db"
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(db_path))
    content = "Enumerate object identifiers and confirm horizontal access; retain only cross-user reads."
    id_a = store.ingest(_inhouse_entry(content, "case-A", "task-A", "ev-a"))
    id_b = store.ingest(_inhouse_entry(content, "case-B", "task-B", "ev-b"))
    # 同内容 → 同一行，不新建
    assert id_a == id_b
    conn = sqlite3.connect(db_path)
    assert conn.execute("SELECT COUNT(*) FROM knowledge").fetchone()[0] == 1
    case_id, source_id = conn.execute("SELECT case_id, source_id FROM knowledge").fetchone()
    # case 引用只留最新的
    assert (case_id, source_id) == ("case-B", "task-B")
    evs = json.loads(conn.execute("SELECT case_evidence FROM knowledge").fetchone()[0])
    # 证据引用取并集
    assert {e["evidence_id"] for e in evs} == {"ev-a", "ev-b"}
    prov = json.loads(conn.execute("SELECT provenance FROM knowledge").fetchone()[0])
    assert prov["case_id"] == "case-B"
    conn.close()


def test_ingest_dedup_only_within_active_new_sources(tmp_path, monkeypatch):
    db_path = tmp_path / "redkb.db"
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(db_path))
    content = "Test upload validation with controlled requests and retain demonstrated execution."
    # legacy 来源不参与 inhouse 去重（不同 source_type 各自一行）
    legacy = _inhouse_entry(content, "case-L", "task-L", "ev-l")
    legacy.source_type = "legacy"
    legacy.legacy_source = "llm-expert"
    legacy.case_id = case_id_for("legacy", "task-L")
    legacy.redacted_content_hash = hash_text(content)
    legacy.content_hash = hash_text(content)
    store.ingest(legacy)
    inhouse_id = store.ingest(_inhouse_entry(content, "case-I", "task-I", "ev-i"))
    conn = sqlite3.connect(db_path)
    assert conn.execute("SELECT COUNT(*) FROM knowledge").fetchone()[0] == 2
    assert conn.execute("SELECT source_type FROM knowledge WHERE id=?", (inhouse_id,)).fetchone()[0] == "inhouse"
    conn.close()


def test_converge_inhouse_duplicates_merges_stats_and_keeps_authoritative(tmp_path, monkeypatch):
    db_path = tmp_path / "redkb.db"
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(db_path))
    content = "Construct a cross-origin state-changing request and confirm the mutation applies."
    ch = hash_text(content)
    store._connect().close()
    conn = sqlite3.connect(db_path)
    conn.execute("SELECT * FROM knowledge").fetchall()  # trigger schema
    cols = ("id", "type", "title", "content", "tags", "scope", "status", "verified", "source_type",
            "source_id", "case_id", "redacted_content_hash", "content_hash", "actual_tool",
            "validation_status", "sanitization_status", "data_quality_status", "usage_count",
            "last_used", "provenance", "created_at", "updated_at")
    base = (None, "attack_primitive", "csrf validation technique", content, None, "all", None, 0,
            "inhouse", None, None, ch, ch, "http_request", "candidate", "sanitized", "active",
            None, None, None, None, None)
    rows = [
        ("kb.dup.old", "candidate", "candidate", 3, "2026-09-20T01:00:00", "case-old", "task-old"),
        ("kb.dup.auth", "authoritative", "verified", 7, "2026-09-25T01:00:00", "case-auth", "task-auth"),
        ("kb.dup.new", "candidate", "candidate", 1, "2026-09-29T01:00:00", "case-new", "task-new"),
    ]
    for eid, status, validation, usage, ts, case_id, source_id in rows:
        values = list(base)
        values[0] = eid
        values[6] = status
        values[9] = source_id
        values[10] = case_id
        values[14] = validation
        values[17] = usage
        values[18] = ts if status != "authoritative" else "2026-09-25T02:00:00"
        values[19] = json.dumps({"case_id": case_id, "source_task": source_id})
        values[20] = ts
        values[21] = ts
        conn.execute(f"INSERT INTO knowledge ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", values)
    conn.commit()
    conn.close()
    store._connect().close()

    result = store.converge_inhouse_duplicates()
    assert result["groups"] == 1
    assert result["deleted_rows"] == 2

    conn = sqlite3.connect(db_path)
    kept = conn.execute("SELECT id, status, usage_count, case_id, source_id FROM knowledge").fetchall()
    assert len(kept) == 1
    eid, status, usage, case_id, source_id = kept[0]
    # authoritative 存活；case 引用取组内最新；usage 求和 3+7+1
    assert status == "authoritative"
    assert usage == 11
    assert (case_id, source_id) == ("case-new", "task-new")
    # 被删行的 versions/governance 一并清理
    assert conn.execute("SELECT COUNT(*) FROM knowledge_versions WHERE knowledge_id IN ('kb.dup.old','kb.dup.new')").fetchone()[0] == 0
    conn.close()
