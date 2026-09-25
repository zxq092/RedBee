"""SQLite-backed RED-KB store with migration, versioning, and governance gates."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from typing import Any, Iterable, Optional

from . import vector
from .case_schema import CaseRecord, CaseSnapshot, EvidenceRef
from .governance import (
    GOVERNANCE_STATUSES,
    NEW_SOURCE_TYPES,
    actor_is_admin,
    actor_is_service,
    case_id_for,
    filter_governance,
    governance_status_for_entry,
    hash_text,
    normalize_source_tuple,
    sanitize_text,
    transition_governance,
)
from .schemas import (
    CaseRef,
    GovernanceRecord,
    KnowledgeEntry,
    PromoteRequest,
    utcnow,
)


DATA_DIR = os.environ.get("REDKB_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "data"))
DB_PATH = os.path.join(DATA_DIR, "redkb.db")

KNOWLEDGE_COLUMNS = [
    "id", "type", "title", "content", "content_redacted", "tags", "scope",
    "status", "verified", "proof_method", "source_type", "source_id", "source_flow",
    "case_id", "legacy_source", "source_ref", "distilled_from", "redacted_content_hash",
    "content_hash", "raw_content_hash", "actual_tool", "validation_status",
    "sanitization_status", "data_quality_status", "case_evidence", "source_evidence",
    "proved_at", "proof_evidence", "preconditions", "cve_id", "affected", "version",
    "cvss", "poc_ref", "usage_count", "success_rate", "last_used", "disabled",
    "coverage_state", "confidence", "provenance", "created_at", "updated_at", "vect",
]
NCOLS = len(KNOWLEDGE_COLUMNS)
COLS = KNOWLEDGE_COLUMNS
CASE_COLUMNS = [
    "id", "source_type", "source_id", "source_flow", "legacy_source", "agent", "task",
    "target", "target_id", "model", "runtime_id", "trajectory", "summary", "status",
    "snapshot_hash", "created_at", "updated_at",
]


class GovernanceError(Exception):
    def __init__(self, status_code: int, code: str, message: str, details: Any = None):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        super().__init__(message)


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    if not _table_exists(conn, table):
        return []
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]


def _add_columns(conn: sqlite3.Connection, table: str, definitions: Iterable[tuple[str, str]]) -> None:
    existing = set(_columns(conn, table))
    for name, definition in definitions:
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def _ensure_table(conn: sqlite3.Connection, sql: str) -> None:
    if not _table_exists(conn, "knowledge") and "knowledge" in sql.lower():
        conn.execute(sql)
    elif not _table_exists(conn, sql.split("(")[0].strip()):
        conn.execute(sql)


def _json(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump()
    elif hasattr(value, "dict"):
        value = value.dict()
    elif isinstance(value, (list, tuple)):
        value = [item.model_dump() if hasattr(item, "model_dump") else item for item in value]
    elif isinstance(value, dict):
        value = {key: item.model_dump() if hasattr(item, "model_dump") else item for key, item in value.items()}
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _parse_json(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _migrate(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS knowledge (
            id TEXT PRIMARY KEY,
            type TEXT, title TEXT, content TEXT, content_redacted TEXT, tags TEXT, scope TEXT,
            status TEXT, verified INTEGER, proof_method TEXT, source_type TEXT, source_id TEXT,
            source_flow TEXT, case_id TEXT, legacy_source TEXT, source_ref TEXT,
            distilled_from TEXT, redacted_content_hash TEXT, content_hash TEXT,
            raw_content_hash TEXT, actual_tool TEXT, validation_status TEXT,
            sanitization_status TEXT, data_quality_status TEXT, case_evidence TEXT,
            source_evidence TEXT, proved_at TEXT, proof_evidence TEXT, preconditions TEXT,
            cve_id TEXT, affected TEXT, version TEXT, cvss REAL, poc_ref TEXT,
            usage_count INTEGER, success_rate REAL, last_used TEXT, disabled INTEGER,
            coverage_state TEXT, confidence REAL, provenance TEXT, created_at TEXT,
            updated_at TEXT, vect BLOB
        )"""
    )
    _add_columns(conn, "knowledge", [
        ("content_redacted", "TEXT"),
        ("source_id", "TEXT"),
        ("source_flow", "TEXT"),
        ("case_id", "TEXT"),
        ("legacy_source", "TEXT"),
        ("source_ref", "TEXT"),
        ("distilled_from", "TEXT"),
        ("redacted_content_hash", "TEXT"),
        ("content_hash", "TEXT"),
        ("raw_content_hash", "TEXT"),
        ("actual_tool", "TEXT"),
        ("validation_status", "TEXT"),
        ("sanitization_status", "TEXT"),
        ("data_quality_status", "TEXT"),
        ("provenance", "TEXT"),
    ])
    conn.execute(
        """CREATE TABLE IF NOT EXISTS knowledge_versions (
            knowledge_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            content_redacted TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(knowledge_id, version)
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS redkb_governance (
            knowledge_id TEXT PRIMARY KEY,
            status TEXT NOT NULL CHECK(status IN ('active','quarantined','disabled','reviewing','rejected')),
            reason_code TEXT, reason TEXT, content_hash TEXT, source_type TEXT NOT NULL,
            source_id TEXT, source_flow TEXT, quarantined_at TEXT, quarantined_by TEXT,
            reviewed_at TEXT, reviewed_by TEXT, audit_json TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS redkb_governance_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            governance_id TEXT NOT NULL,
            before_status TEXT,
            after_status TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            reason TEXT NOT NULL,
            batch_id TEXT,
            created_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY, source_type TEXT NOT NULL, source_id TEXT NOT NULL,
            source_flow TEXT, legacy_source TEXT, agent TEXT, task TEXT, target TEXT,
            target_id TEXT, model TEXT, runtime_id TEXT, trajectory TEXT NOT NULL,
            summary TEXT, status TEXT NOT NULL DEFAULT 'new', snapshot_hash TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            UNIQUE(source_type, source_id)
        )"""
    )
    _add_columns(conn, "cases", [
        ("source_type", "TEXT"),
        ("source_id", "TEXT"),
        ("source_flow", "TEXT"),
        ("legacy_source", "TEXT"),
        ("target_id", "TEXT"),
        ("runtime_id", "TEXT"),
        ("status", "TEXT"),
        ("snapshot_hash", "TEXT"),
        ("updated_at", "TEXT"),
    ])
    conn.execute(
        """CREATE TABLE IF NOT EXISTS case_snapshots (
            case_id TEXT PRIMARY KEY,
            source_type TEXT NOT NULL CHECK(source_type IN ('pentagi','inhouse','legacy')),
            source_id TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            snapshot_hash TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('new','running','done','error','needs_review')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(source_type, source_id)
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS case_evidence (
            evidence_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES case_snapshots(case_id),
            kind TEXT NOT NULL,
            content TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            evidence_hash TEXT,
            access_level TEXT NOT NULL DEFAULT 'restricted',
            sanitization_status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            retention_policy TEXT,
            UNIQUE(case_id, content_hash)
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS ingest_entities (
            source_type TEXT NOT NULL CHECK(source_type IN ('pentagi','inhouse','legacy')),
            source_id TEXT NOT NULL,
            entity_type TEXT NOT NULL CHECK(entity_type IN ('case','candidate','distilled','promoted','sync')),
            entity_id TEXT NOT NULL,
            status TEXT NOT NULL,
            content_hash TEXT,
            remote_doc_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(source_type, source_id, entity_type, entity_id)
        )"""
    )

    _migrate_knowledge(conn)
    _migrate_cases(conn)
    conn.commit()


def _migrate_knowledge(conn: sqlite3.Connection) -> None:
    columns = set(_columns(conn, "knowledge"))
    rows = conn.execute("SELECT * FROM knowledge").fetchall()
    for row in rows:
        values = dict(zip(_columns(conn, "knowledge"), row))
        old_source = values.get("source_type") or "legacy"
        source_type, legacy_source = normalize_source_tuple(old_source, values.get("legacy_source"))
        raw_content = values.get("content") or ""
        check = sanitize_text(raw_content)
        content_redacted = check.content if check.sanitized else raw_content
        raw_hash = values.get("raw_content_hash") or check.raw_content_hash or hash_text(raw_content)
        redacted_hash = values.get("redacted_content_hash") or check.redacted_content_hash or hash_text(content_redacted)
        old_status = str(values.get("status") or "candidate")
        existing_validation = values.get("validation_status")
        if not existing_validation:
            if old_status == "verified":
                existing_validation = "verified"
            elif old_status == "candidate":
                existing_validation = "candidate"
            else:
                existing_validation = "unverified"
        validation_status = str(existing_validation)
        if source_type not in NEW_SOURCE_TYPES or not check.sanitized:
            data_quality = "reviewing"
            status = "needs_review"
            sanitization = "needs_review" if not check.sanitized else (values.get("sanitization_status") or "sanitized")
        else:
            data_quality = str(values.get("data_quality_status") or "active")
            status = str(values.get("status") or old_status)
            sanitization = str(values.get("sanitization_status") or "sanitized")
        case_id = values.get("case_id") or case_id_for(source_type, str(values.get("source_id") or values.get("id") or ""))
        try:
            version = int(str(values.get("version") or 1).split("-")[0].split(".")[0] or 1)
        except (TypeError, ValueError):
            version = 1
        now = utcnow()
        content = content_redacted if check.sanitized else raw_content
        sql = """INSERT INTO knowledge (
                id,type,title,content,content_redacted,tags,scope,status,verified,proof_method,
                source_type,source_id,source_flow,case_id,legacy_source,source_ref,distilled_from,
                redacted_content_hash,content_hash,raw_content_hash,actual_tool,validation_status,
                sanitization_status,data_quality_status,case_evidence,source_evidence,proved_at,
                proof_evidence,preconditions,cve_id,affected,version,cvss,poc_ref,usage_count,
                success_rate,last_used,disabled,coverage_state,confidence,provenance,created_at,
                updated_at,vect
            ) VALUES (""" + ",".join(["?"] * len(KNOWLEDGE_COLUMNS)) + """)
            ON CONFLICT(id) DO UPDATE SET
                type=excluded.type, content=excluded.content, content_redacted=excluded.content_redacted,
                tags=excluded.tags, scope=excluded.scope, status=excluded.status,
                verified=excluded.verified, proof_method=excluded.proof_method,
                source_type=excluded.source_type, source_id=excluded.source_id,
                source_flow=excluded.source_flow, case_id=excluded.case_id,
                legacy_source=excluded.legacy_source, source_ref=excluded.source_ref,
                distilled_from=excluded.distilled_from,
                redacted_content_hash=excluded.redacted_content_hash,
                content_hash=excluded.content_hash, raw_content_hash=excluded.raw_content_hash,
                actual_tool=excluded.actual_tool, validation_status=excluded.validation_status,
                sanitization_status=excluded.sanitization_status,
                data_quality_status=excluded.data_quality_status,
                case_evidence=excluded.case_evidence, source_evidence=excluded.source_evidence,
                proved_at=excluded.proved_at, proof_evidence=excluded.proof_evidence,
                preconditions=excluded.preconditions, cve_id=excluded.cve_id,
                affected=excluded.affected, version=excluded.version, cvss=excluded.cvss,
                poc_ref=excluded.poc_ref, usage_count=excluded.usage_count,
                success_rate=excluded.success_rate, last_used=excluded.last_used,
                disabled=excluded.disabled, coverage_state=excluded.coverage_state,
                confidence=excluded.confidence, provenance=excluded.provenance,
                updated_at=excluded.updated_at"""
        conn.execute(sql, (
                values.get("id"), values.get("type"), values.get("title"), content, content_redacted,
                values.get("tags") or "[]", values.get("scope") or "all", status,
                int(bool(values.get("verified"))), values.get("proof_method"), source_type,
                values.get("source_id"), values.get("source_flow"), case_id, legacy_source,
                values.get("source_ref"), values.get("distilled_from"), redacted_hash, raw_hash,
                raw_hash, values.get("actual_tool"), validation_status, sanitization, data_quality,
                values.get("case_evidence") or "[]", values.get("source_evidence"),
                values.get("proved_at"), values.get("proof_evidence"), values.get("preconditions"),
                values.get("cve_id"), values.get("affected"), version, values.get("cvss"),
                values.get("poc_ref"), values.get("usage_count"), values.get("success_rate"),
                values.get("last_used"), int(bool(values.get("disabled"))),
                values.get("coverage_state") or None, values.get("confidence") if values.get("confidence") is not None else 0.9,
                _json({"migrated": True, "legacy_source": legacy_source}), now, now,
                values.get("vect"),
            ),
        )
        if conn.execute("SELECT 1 FROM knowledge_versions WHERE knowledge_id=? AND version=?", (values.get("id"), version)).fetchone() is None:
            conn.execute(
                "INSERT INTO knowledge_versions(knowledge_id,version,content_hash,content_redacted,created_at) VALUES (?,?,?,?,?)",
                (values.get("id"), version, raw_hash, content_redacted, now),
            )
        if conn.execute("SELECT 1 FROM redkb_governance WHERE knowledge_id=?", (values.get("id"),)).fetchone() is None:
            reason_code = "unclassified-legacy" if source_type == "legacy" else "migration-default"
            conn.execute(
                """INSERT INTO redkb_governance(
                    knowledge_id,status,reason_code,reason,content_hash,source_type,source_id,
                    source_flow,quarantined_at,quarantined_by,reviewed_at,reviewed_by,audit_json,
                    created_at,updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    values.get("id"), "reviewing", reason_code,
                    "migration default: explicit governance review required", raw_hash, source_type,
                    values.get("source_id"), values.get("source_flow"), None, None, None, None,
                    _json({"batch": "migration", "reason_code": reason_code}), now, now,
                ),
            )


def _migrate_cases(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT * FROM cases").fetchall()
    old_cols = _columns(conn, "cases")
    for row in rows:
        values = dict(zip(old_cols, row))
        cid = values.get("id")
        source_type, legacy_source = normalize_source_tuple(values.get("source_type") or "legacy", values.get("legacy_source"))
        source_id = values.get("source_id") or cid or values.get("task") or ""
        now = utcnow()
        snapshot_hash = values.get("snapshot_hash") or hash_text(values.get("trajectory") or "")
        conn.execute(
            """INSERT INTO cases (
                id,source_type,source_id,source_flow,legacy_source,agent,task,target,target_id,
                model,runtime_id,trajectory,summary,status,snapshot_hash,created_at,updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                source_type=excluded.source_type,source_id=excluded.source_id,
                source_flow=excluded.source_flow,legacy_source=excluded.legacy_source,
                agent=excluded.agent,task=excluded.task,target=excluded.target,
                target_id=excluded.target_id,model=excluded.model,runtime_id=excluded.runtime_id,
                trajectory=excluded.trajectory,summary=excluded.summary,status=excluded.status,
                snapshot_hash=excluded.snapshot_hash,updated_at=excluded.updated_at""",
            (
                cid, source_type, source_id, values.get("source_flow"), legacy_source,
                values.get("agent"), values.get("task"), values.get("target"), values.get("target_id"),
                values.get("model"), values.get("runtime_id"), values.get("trajectory") or "{}",
                values.get("summary"), values.get("status") or "new", snapshot_hash,
                values.get("created_at") or now, now,
            ),
        )
        if conn.execute("SELECT 1 FROM case_snapshots WHERE case_id=?", (cid,)).fetchone() is None:
            snapshot = {
                "schema_version": 1,
                "source_type": source_type,
                "source_id": source_id,
                "source_flow": values.get("source_flow"),
                "legacy_source": legacy_source,
                "agent": values.get("agent"),
                "model": values.get("model"),
                "runtime_id": values.get("runtime_id"),
                "task": values.get("task"),
                "target": values.get("target"),
                "target_id": values.get("target_id") or values.get("target"),
                "modules": [],
                "phases": [],
                "findings": [],
                "coverage": [],
                "trajectory": {"tool_calls": [], "llm_turns": {"count": 0}, "raw_evidence_ref": []},
                "provenance": {"captured_at": values.get("created_at") or now, "adapter_version": "migration", "raw_size_bytes": len(values.get("trajectory") or ""), "sanitized": True},
            }
            conn.execute(
                """INSERT INTO case_snapshots(case_id,source_type,source_id,snapshot_json,snapshot_hash,status,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (cid, source_type, source_id, _json(snapshot), snapshot_hash, "needs_review", now, now),
            )


def _connect() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    _migrate(conn)
    return conn


def _row_to_map(row: tuple, columns: list[str] | None = None) -> dict:
    columns = columns or _columns_from_row(row)
    return {name: row[index] for index, name in enumerate(columns)}


def _columns_from_row(row: tuple) -> list[str]:
    if hasattr(row, "keys"):
        return list(row.keys())
    return KNOWLEDGE_COLUMNS[: len(row)]


def _row_to_entry(row: tuple) -> KnowledgeEntry:
    row_cols = _columns_from_row(row)
    values = _row_to_map(row, row_cols)
    values.pop("vect", None)
    values["tags"] = _parse_json(values.get("tags"), [])
    values["case_evidence"] = _parse_json(values.get("case_evidence"), [])
    values["coverage_state"] = _parse_json(values.get("coverage_state"), None)
    values["provenance"] = _parse_json(values.get("provenance"), {})
    values["verified"] = bool(values.get("verified"))
    values["disabled"] = bool(values.get("disabled"))
    if values.get("version") in (None, ""):
        values["version"] = 1
    if values.get("usage_count") is None:
        values["usage_count"] = 0
    if values.get("confidence") is None:
        values["confidence"] = 0.9
    if not values.get("content_redacted"):
        values["content_redacted"] = values.get("content") or ""
    if not values.get("created_at"):
        values["created_at"] = utcnow()
    if not values.get("updated_at"):
        values["updated_at"] = values["created_at"]
    if not values.get("status"):
        values["status"] = "needs_review"
    if not values.get("sanitization_status"):
        values["sanitization_status"] = "needs_review"
    if not values.get("data_quality_status"):
        values["data_quality_status"] = "reviewing"
    if not values.get("validation_status"):
        values["validation_status"] = "unverified"
    if not values.get("source_type"):
        values["source_type"] = "legacy"
    return KnowledgeEntry(**values)


def _public_entry(entry: KnowledgeEntry) -> KnowledgeEntry:
    data = entry.model_dump()
    for key in ("content_hash", "raw_content_hash", "redacted_content_hash", "case_evidence", "source_evidence", "proof_evidence", "proof_method", "proved_at"):
        data.pop(key, None)
    data["status"] = entry.status
    data["verified"] = entry.verified
    return KnowledgeEntry(**data)


def _text_of(entry: KnowledgeEntry) -> str:
    return f"{entry.title} {entry.content_redacted or entry.content} {' '.join(entry.tags)} {entry.cve_id or ''} {entry.affected or ''}".strip()


def _vect_of(entry: KnowledgeEntry) -> Optional[bytes]:
    if not vector.enabled():
        return None
    try:
        return vector.pack(vector.embed(_text_of(entry)))
    except Exception:
        return None


def _entry_to_row(entry: KnowledgeEntry, vec_blob: Optional[bytes] = None) -> tuple:
    return (
        entry.id, entry.type, entry.title, entry.content_redacted or entry.content,
        entry.content_redacted or entry.content, _json(entry.tags), entry.scope, entry.status,
        int(entry.verified), entry.proof_method, entry.source_type, entry.source_id,
        entry.source_flow, entry.case_id, entry.legacy_source, entry.source_ref,
        entry.distilled_from, entry.redacted_content_hash, entry.content_hash,
        entry.raw_content_hash, entry.actual_tool, entry.validation_status,
        entry.sanitization_status, entry.data_quality_status, _json(entry.case_evidence),
        entry.source_evidence, entry.proved_at, entry.proof_evidence, entry.preconditions,
        entry.cve_id, entry.affected, entry.version or 1, entry.cvss, entry.poc_ref,
        entry.usage_count, entry.success_rate, entry.last_used, int(entry.disabled),
        _json(entry.coverage_state) if entry.coverage_state else None, entry.confidence,
        _json(entry.provenance), entry.created_at or utcnow(), entry.updated_at or utcnow(),
        vec_blob,
    )


def _governance_row(conn: sqlite3.Connection, eid: str) -> dict | None:
    row = conn.execute("SELECT * FROM redkb_governance WHERE knowledge_id=?", (eid,)).fetchone()
    if not row:
        return None
    cols = [d[1] for d in conn.execute("PRAGMA table_info(redkb_governance)").fetchall()]
    return dict(zip(cols, row))


def _set_governance(conn: sqlite3.Connection, eid: str, status: str, actor: str, reason_code: str, reason: str, before: str | None = None, batch_id: str | None = None,
                    source_type: str = "legacy", source_id: str | None = None, source_flow: str | None = None) -> None:
    now = utcnow()
    current = _governance_row(conn, eid)
    old_status = str(current.get("status") if current else "reviewing")
    if before is not None:
        old_status = before
    try:
        transition_governance(old_status, status, actor, reason_code, reason, batch_id)
    except ValueError:
        if old_status == status:
            pass
        else:
            old_status = "reviewing"
            transition_governance(old_status, status, actor, reason_code, reason, batch_id)
    current_hash = _governance_row(conn, eid) and _governance_row(conn, eid).get("content_hash")
    current_source = _governance_row(conn, eid) or {}
    current_source = {
        "source_type": current_source.get("source_type") or source_type,
        "source_id": current_source.get("source_id") or source_id,
        "source_flow": current_source.get("source_flow") or source_flow,
    }
    conn.execute(
        """INSERT INTO redkb_governance(
            knowledge_id,status,reason_code,reason,content_hash,source_type,source_id,
            source_flow,quarantined_at,quarantined_by,reviewed_at,reviewed_by,audit_json,
            created_at,updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(knowledge_id) DO UPDATE SET status=excluded.status,reason_code=excluded.reason_code,
        reason=excluded.reason,content_hash=excluded.content_hash,source_type=excluded.source_type,
        source_id=excluded.source_id,source_flow=excluded.source_flow,
        quarantined_at=CASE WHEN excluded.status='quarantined' THEN excluded.quarantined_at ELSE redkb_governance.quarantined_at END,
        quarantined_by=CASE WHEN excluded.status='quarantined' THEN excluded.quarantined_by ELSE redkb_governance.quarantined_by END,
        reviewed_at=CASE WHEN excluded.status='active' THEN excluded.reviewed_at ELSE redkb_governance.reviewed_at END,
        reviewed_by=CASE WHEN excluded.status='active' THEN excluded.reviewed_by ELSE redkb_governance.reviewed_by END,
        audit_json=redkb_governance.audit_json,updated_at=excluded.updated_at""",
        (
            eid, status, reason_code, reason, current_hash,
            current_source.get("source_type") or "legacy", current_source.get("source_id"),
            current_source.get("source_flow"),
            now if status == "quarantined" else None, actor if status == "quarantined" else None,
            now if status == "active" else None, actor if status == "active" else None,
            _json({"actor": actor, "reason_code": reason_code, "batch_id": batch_id}), now, now,
        ),
    )
    conn.execute(
        """INSERT INTO redkb_governance_audit(governance_id,before_status,after_status,actor,reason_code,reason,batch_id,created_at)
        VALUES (?,?,?,?,?,?,?,?)""",
        (eid, old_status, status, actor, reason_code, reason, batch_id, now),
    )


def _actor_allowed(actor: str | None) -> bool:
    return actor_is_service(actor) or actor_is_admin(actor)


def ingest(entry: KnowledgeEntry | dict[str, Any]) -> str:
    entry = KnowledgeEntry.model_validate(entry)
    source_type, legacy_source = normalize_source_tuple(entry.source_type or "legacy", entry.legacy_source)
    entry.source_type = source_type
    entry.legacy_source = legacy_source
    check = sanitize_text(entry.content_redacted or entry.content)
    now = utcnow()
    if not check.sanitized:
        entry.sanitization_status = "quarantined" if check.reason_code == "kb-query-command" else "needs_review"
        entry.data_quality_status = "quarantined" if entry.sanitization_status == "quarantined" else "reviewing"
        entry.validation_status = "unverified"
        entry.status = "needs_review"
        entry.verified = False
    elif source_type not in NEW_SOURCE_TYPES:
        entry.sanitization_status = "sanitized"
        entry.data_quality_status = "reviewing"
        entry.status = "needs_review"
        entry.validation_status = "unverified"
        entry.verified = False
    elif entry.status == "authoritative":
        entry.status = "needs_review"
        entry.data_quality_status = "reviewing"
        entry.validation_status = "unverified"
        entry.verified = False
    else:
        entry.sanitization_status = "sanitized"
        entry.data_quality_status = "active"
        if entry.validation_status not in {"candidate", "verified"}:
            entry.validation_status = "candidate"
        if entry.status not in {"candidate", "disabled"}:
            entry.status = "candidate"
    entry.redacted_content_hash = entry.redacted_content_hash or hash_text(entry.content_redacted or entry.content)
    entry.content_hash = entry.content_hash or check.raw_content_hash or hash_text(entry.content_redacted or entry.content)
    entry.raw_content_hash = entry.raw_content_hash or entry.content_hash
    entry.version = entry.version or 1
    entry.id = entry.id or f"kb_{uuid.uuid4().hex[:10]}"
    entry.created_at = entry.created_at or now
    entry.updated_at = now

    conn = _connect()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT version,redacted_content_hash,status FROM knowledge WHERE id=?", (entry.id,))
            existing = cur.fetchone()
            if existing and existing[1] == entry.redacted_content_hash:
                return entry.id
            current_version = int(existing[0]) if existing else 0
            vec = _vect_of(entry) if governance_status_for_entry(entry) == "active" else None
            cur.execute(
                "INSERT INTO knowledge_versions(knowledge_id,version,content_hash,content_redacted,created_at) VALUES (?,?,?,?,?)",
                (entry.id, current_version + 1, entry.content_hash, entry.content_redacted or entry.content, now),
            )
            update_set = ",".join(f"{column}=excluded.{column}" for column in KNOWLEDGE_COLUMNS if column != "id")
            cur.execute(
                f"INSERT INTO knowledge ({','.join(KNOWLEDGE_COLUMNS)}) VALUES ({','.join(['?']*NCOLS)}) ON CONFLICT(id) DO UPDATE SET {update_set}",
                _entry_to_row(entry, vec),
            )
            _set_governance(
                conn, entry.id, "active" if governance_status_for_entry(entry) == "active" else governance_status_for_entry(entry),
                "auto_ingest", "ingest-governance", "candidate accepted by governance gate" if governance_status_for_entry(entry) == "active" else "ingest governance gate",
                source_type=entry.source_type, source_id=entry.source_id, source_flow=entry.source_flow,
            )
        return entry.id
    finally:
        conn.close()


def promote(eid: str, req: PromoteRequest | dict[str, Any], actor: str | None = None) -> Optional[KnowledgeEntry]:
    if not _actor_allowed(actor):
        raise GovernanceError(403, "actor-forbidden", "promote requires an authenticated service or admin actor")
    req = PromoteRequest.model_validate(req)
    conn = _connect()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM knowledge WHERE id=?", (eid,))
            row = cur.fetchone()
            if not row:
                return None
            entry = _row_to_entry(row)
            gov = _governance_row(conn, eid)
            if not gov:
                raise GovernanceError(409, "governance-missing", "entry has no governance record")
            if gov["status"] != "active":
                raise GovernanceError(403, "governance-restricted", "entry is not active", {"status": gov["status"]})
            if entry.source_type != req.source_type or str(entry.source_id or "") != str(req.source_id):
                raise GovernanceError(403, "source-mismatch", "promotion source does not match entry")
            if req.source_flow != entry.source_flow:
                raise GovernanceError(403, "source-flow-mismatch", "promotion source_flow does not match entry")
            if req.case_id != entry.case_id:
                raise GovernanceError(403, "case-mismatch", "promotion case_id does not match entry")
            if entry.redacted_content_hash != req.content_hash:
                raise GovernanceError(409, "content-hash-mismatch", "promotion content hash does not match current version")
            if entry.validation_status != "verified" or not entry.verified or not req.verified:
                raise GovernanceError(409, "not-verified", "candidate must be verified before promotion")
            if req.proof_method not in {"system", "replay", "human"}:
                raise GovernanceError(409, "proof-method-invalid", "invalid proof method")
            if not req.case_evidence:
                raise GovernanceError(409, "case-evidence-missing", "promotion requires restricted evidence refs")
            for ref in req.case_evidence:
                if not ref.evidence_hash:
                    raise GovernanceError(409, "evidence-hash-missing", "evidence hash is required")
            current_version = int(entry.version or 0)
            updated = entry.model_copy(update={
                "status": "authoritative",
                "verified": True,
                "proof_method": req.proof_method,
                "validated_at": utcnow(),
                "updated_at": utcnow(),
            })
            vec_blob = row["vect"] if "vect" in row.keys() else None
            cur.execute(
                f"UPDATE knowledge SET {','.join(f'{c}=?' for c in KNOWLEDGE_COLUMNS if c != 'id')} WHERE id=? AND version=?",
                _entry_to_row(updated, vec_blob)[1:] + (eid, current_version),
            )
            if cur.rowcount != 1:
                raise GovernanceError(409, "optimistic-lock-conflict", "entry version changed during promotion")
            _set_governance(conn, eid, "active", actor or "auto_ingest", "promoted", "promotion completed", before=gov["status"])
        return _row_to_entry(cur.execute("SELECT * FROM knowledge WHERE id=?", (eid,)).fetchone())
    finally:
        conn.close()


def retract(eid: str, actor: str | None = None, reason_code: str = "retired", reason: str = "retracted by authorized actor") -> Optional[KnowledgeEntry]:
    if not _actor_allowed(actor):
        raise GovernanceError(403, "actor-forbidden", "retract requires an authenticated service or admin actor")
    conn = _connect()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM knowledge WHERE id=?", (eid,))
            row = cur.fetchone()
            if not row:
                return None
            entry = _row_to_entry(row)
            if entry.status not in {"authoritative", "verified"} or not entry.verified:
                raise GovernanceError(409, "invalid-retract-state", "only verified authoritative entries can be retracted")
            current_version = int(entry.version or 0)
            updated = entry.model_copy(update={
                "status": "revoked",
                "verified": False,
                "proof_method": None,
                "validated_at": None,
                "updated_at": utcnow(),
            })
            vec_blob = row["vect"] if "vect" in row.keys() else None
            cur.execute(
                f"UPDATE knowledge SET {','.join(f'{c}=?' for c in KNOWLEDGE_COLUMNS if c != 'id')} WHERE id=? AND version=?",
                _entry_to_row(updated, vec_blob)[1:] + (eid, current_version),
            )
            if cur.rowcount != 1:
                raise GovernanceError(409, "optimistic-lock-conflict", "entry version changed during retract")
            _set_governance(conn, eid, "reviewing", actor, reason_code, reason)
        return _row_to_entry(cur.execute("SELECT * FROM knowledge WHERE id=?", (eid,)).fetchone())
    finally:
        conn.close()


def _filtered_rows(conn: sqlite3.Connection, include_candidates: bool = False) -> list[tuple]:
    rows = conn.execute("SELECT * FROM knowledge").fetchall()
    out = []
    for row in rows:
        entry = _row_to_entry(row)
        if governance_status_for_entry(entry) != "active":
            continue
        if entry.status == "candidate" and not (include_candidates or entry.verified):
            continue
        out.append(row)
    return out


def query(text: str, types=None, tags=None, limit: int = 5,
          include_candidates: bool = False) -> List[KnowledgeEntry]:
    conn = _connect()
    try:
        rows = _filtered_rows(conn, include_candidates)
        qvec = None
        semantic_ok = False
        if vector.enabled():
            try:
                qvec = vector.embed(text)
                semantic_ok = True
            except Exception:
                semantic_ok = False
        tokens = [t for t in text.lower().split() if t]
        scored: list[tuple[float, KnowledgeEntry]] = []
        for row in rows:
            entry = _public_entry(_row_to_entry(row))
            if types and entry.type not in types:
                continue
            if tags and not any(tag in entry.tags for tag in tags):
                continue
            blob = f"{entry.title} {entry.content_redacted or entry.content} {' '.join(entry.tags)} {entry.cve_id or ''} {entry.affected or ''}".lower()
            weight = 0.0
            if entry.cve_id and entry.cve_id.lower() == text.strip().lower():
                weight += 10
            weight += sum(2 for token in tokens if token in entry.title.lower())
            weight += sum(1 for token in tokens if token in blob)
            row_vec = row["vect"] if "vect" in row.keys() else None
            if semantic_ok and row_vec is not None:
                try:
                    weight += vector.cosine(qvec, vector.unpack(row_vec)) * 4.0
                except Exception:
                    pass
            if weight > 0:
                weight *= 1.0 if entry.status == "authoritative" else 0.4
                weight += entry.confidence
                scored.append((weight, entry))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [entry for _, entry in scored[:limit]]
    finally:
        conn.close()


def list_knowledge() -> List[KnowledgeEntry]:
    conn = _connect()
    try:
        return [_public_entry(_row_to_entry(row)) for row in _filtered_rows(conn)]
    finally:
        conn.close()


def get_knowledge(eid: str) -> Optional[KnowledgeEntry]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM knowledge WHERE id=?", (eid,)
        ).fetchone()
        if row is None:
            return None
        entry = _row_to_entry(row)
        # 按 ID 直接取：仅要求治理为 active(可被检索)。
        # 与 query/list 的 _filtered_rows 不同——这里不再额外跳过"未验证的 candidate"，
        # 否则刚 promote 入库的 candidate 读不回来(见 auto_ingest.promote_inhouse_candidate)。
        if governance_status_for_entry(entry) != "active":
            return None
        return _public_entry(entry)
    finally:
        conn.close()


def coverage(scope: str) -> Optional[dict]:
    conn = _connect()
    try:
        rows = _filtered_rows(conn)
        for row in rows:
            entry = _row_to_entry(row)
            if entry.type != "target_profile" or entry.scope != scope:
                continue
            cs = entry.coverage_state or {}
            surface, resolved = cs.get("surface", []), cs.get("resolved", [])
            pct = round(len(resolved) / len(surface) * 100, 1) if surface else 0.0
            return {"scope": scope, "surface": surface, "resolved": resolved, "coverage": pct, "remaining": list(set(surface) - set(resolved))}
        return None
    finally:
        conn.close()


def _case_values(record: Any) -> dict:
    if isinstance(record, CaseSnapshot):
        return {
            "id": record.case_id,
            "source_type": record.source_type,
            "source_id": record.source_id,
            "source_flow": record.source_flow,
            "legacy_source": record.legacy_source,
            "agent": record.agent,
            "task": record.task,
            "target": record.target,
            "target_id": record.target_id,
            "model": record.model,
            "runtime_id": record.runtime_id,
            "trajectory": _json(record.trajectory.model_dump()),
            "snapshot_json": _json(record.model_dump()),
            "summary": "",
            "status": "new",
            "snapshot_hash": hash_text(_json(record.model_dump())),
            "created_at": record.provenance.captured_at or utcnow(),
            "updated_at": utcnow(),
        }
    if isinstance(record, CaseRecord):
        snapshot = record.to_snapshot()
        return {
            "id": snapshot.case_id,
            "source_type": snapshot.source_type,
            "source_id": snapshot.source_id,
            "source_flow": snapshot.source_flow,
            "legacy_source": snapshot.legacy_source,
            "agent": snapshot.agent,
            "task": snapshot.task,
            "target": snapshot.target,
            "target_id": snapshot.target_id,
            "model": snapshot.model,
            "runtime_id": snapshot.runtime_id,
            "trajectory": _json(snapshot.trajectory.model_dump()),
            "snapshot_json": _json(snapshot.model_dump()),
            "summary": record.summary,
            "status": "new",
            "snapshot_hash": hash_text(_json(snapshot.model_dump())),
            "created_at": record.created_at or utcnow(),
            "updated_at": utcnow(),
        }
    if isinstance(record, dict):
        values = dict(record)
        source_type, legacy_source = normalize_source_tuple(values.get("source_type") or "legacy", values.get("legacy_source"))
        cid = values.get("id") or case_id_for(source_type, str(values.get("source_id") or values.get("task") or ""))
        values.update({
            "id": cid, "source_type": source_type, "source_id": values.get("source_id") or values.get("task") or cid,
            "source_flow": values.get("source_flow"), "legacy_source": legacy_source,
            "agent": values.get("agent", "unknown"), "task": values.get("task", ""),
            "target": values.get("target", ""), "target_id": values.get("target_id") or values.get("target"),
            "model": values.get("model", "unknown"), "runtime_id": values.get("runtime_id"),
            "trajectory": _json(values.get("trajectory") or {}), "snapshot_json": _json(values.get("snapshot") or values.get("snapshot_json") or {}), "summary": values.get("summary", ""),
            "status": values.get("status", "new"), "snapshot_hash": values.get("snapshot_hash") or hash_text(values.get("trajectory") or {}),
            "created_at": values.get("created_at") or utcnow(), "updated_at": utcnow(),
        })
        return values
    raise TypeError("record must be CaseSnapshot, CaseRecord, or dict")


def submit_case(record: Any) -> str:
    values = _case_values(record)
    conn = _connect()
    try:
        with conn:
            conn.execute(
                f"INSERT INTO cases ({','.join(CASE_COLUMNS)}) VALUES ({','.join(['?']*len(CASE_COLUMNS))}) "
                f"ON CONFLICT(id) DO UPDATE SET source_type=excluded.source_type,source_id=excluded.source_id,"
                f"source_flow=excluded.source_flow,legacy_source=excluded.legacy_source,agent=excluded.agent,"
                f"task=excluded.task,target=excluded.target,target_id=excluded.target_id,model=excluded.model,"
                f"runtime_id=excluded.runtime_id,trajectory=excluded.trajectory,summary=excluded.summary,"
                f"status=excluded.status,snapshot_hash=excluded.snapshot_hash,updated_at=excluded.updated_at",
                tuple(values.get(column) for column in CASE_COLUMNS),
            )
            if values.get("snapshot_json"):
                conn.execute(
                    """INSERT OR REPLACE INTO case_snapshots(
                        case_id,source_type,source_id,snapshot_json,snapshot_hash,status,created_at,updated_at
                    ) VALUES (?,?,?,?,?,?,?,?)""",
                    (
                        values["id"], values["source_type"], values["source_id"],
                        values["snapshot_json"], values["snapshot_hash"], values["status"],
                        values["created_at"], values["updated_at"],
                    ),
                )
        return str(values["id"])
    finally:
        conn.close()


def add_case_evidence(case_id: str, evidence_id: str, content: str, kind: str = "finding",
                      evidence_hash: str | None = None, access_level: str = "restricted",
                      sanitization_status: str = "sanitized") -> str:
    check = sanitize_text(content or "")
    content = check.content
    evidence_hash = (evidence_hash or hash_text(content)).lower()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", evidence_hash):
        raise ValueError("evidence_hash must be a SHA-256 hex digest")
    now = utcnow()
    conn = _connect()
    try:
        with conn:
            exists = conn.execute("SELECT 1 FROM case_snapshots WHERE case_id=?", (case_id,)).fetchone()
            if not exists:
                raise ValueError("case snapshot not found")
            conn.execute(
                """INSERT OR IGNORE INTO case_evidence(
                    evidence_id,case_id,kind,content,content_hash,evidence_hash,
                    access_level,sanitization_status,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    evidence_id, case_id, kind, content, hash_text(content), evidence_hash,
                    access_level, sanitization_status, now,
                ),
            )
        return evidence_id
    finally:
        conn.close()


def get_case_snapshot(cid: str) -> Optional[dict]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT case_id,source_type,source_id,snapshot_json,snapshot_hash,status,created_at,updated_at "
            "FROM case_snapshots WHERE case_id=?", (cid,),
        ).fetchone()
        if not row:
            return None
        snapshot = _parse_json(row["snapshot_json"], {})
        values = dict(snapshot)
        values["snapshot_json"] = snapshot
        values.update({
            "case_id": row["case_id"],
            "snapshot_hash": row["snapshot_hash"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
        return values
    finally:
        conn.close()


def get_case(cid: str) -> Optional[dict]:
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
        if not row:
            return None
        cols = [d[1] for d in conn.execute("PRAGMA table_info(cases)").fetchall()]
        values = dict(zip(cols, row))
        return {key: _parse_json(value, value) for key, value in values.items()}
    finally:
        conn.close()


def list_cases() -> List[CaseRef]:
    conn = _connect()
    try:
        rows = conn.execute("SELECT id,agent,target,model,summary,created_at FROM cases ORDER BY created_at DESC").fetchall()
        return [CaseRef(id=r[0], agent=r[1] or "", target=r[2] or "", model=r[3] or "", summary=r[4] or "", created_at=r[5] or "") for r in rows]
    finally:
        conn.close()


def get_restricted_evidence(evidence_id: str, actor: str | None = None) -> Optional[dict]:
    if not _actor_allowed(actor):
        raise GovernanceError(403, "actor-forbidden", "restricted evidence requires an authenticated service or admin actor")
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM case_evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
        if not row:
            return None
        cols = [d[1] for d in conn.execute("PRAGMA table_info(case_evidence)").fetchall()]
        return dict(zip(cols, row))
    finally:
        conn.close()


def get_governance(eid: str, actor: str | None = None) -> Optional[dict]:
    if not actor_is_admin(actor):
        raise GovernanceError(403, "actor-forbidden", "governance audit requires an admin actor")
    conn = _connect()
    try:
        row = _governance_row(conn, eid)
        if not row:
            return None
        return row
    finally:
        conn.close()


def audit_governance(eid: str, actor: str, reason_code: str, reason: str, batch_id: str | None = None) -> None:
    if not _actor_allowed(actor):
        raise GovernanceError(403, "actor-forbidden", "governance audit requires an authenticated actor")
    conn = _connect()
    try:
        _set_governance(conn, eid, "reviewing", actor, reason_code, reason, batch_id=batch_id)
    finally:
        conn.close()


__all__ = [
    "CASE_COLUMNS",
    "COLS",
    "GovernanceError",
    "KNOWLEDGE_COLUMNS",
    "add_case_evidence",
    "audit_governance",
    "coverage",
    "get_case",
    "get_case_snapshot",
    "get_governance",
    "get_knowledge",
    "get_restricted_evidence",
    "ingest",
    "list_cases",
    "list_knowledge",
    "promote",
    "query",
    "retract",
    "submit_case",
]
