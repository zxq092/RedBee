"""Shared RED-KB request, knowledge, case, and candidate schemas."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .case_schema import CaseRecord as _CaseRecord
from .case_schema import CaseReview, CaseSnapshot, EvidenceRef
from .governance import NEW_SOURCE_TYPES, normalize_source_type


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class KnowledgeEntry(StrictModel):
    id: Optional[str] = None
    type: str = Field(..., description="attack_primitive|poc|code|cve_entry|trap|strategy_rule|defense_fingerprint|vuln_pattern|guide|answer|target_profile")
    title: str
    content: str
    content_redacted: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    scope: str = "all"

    status: str = "candidate"
    verified: bool = False
    proof_method: Optional[str] = None
    source_type: str = "legacy"
    source_id: Optional[str] = None
    source_flow: Optional[str] = None
    case_id: Optional[str] = None
    source_ref: Optional[str] = None
    legacy_source: Optional[str] = None
    distilled_from: Optional[str] = None
    redacted_content_hash: Optional[str] = None
    content_hash: Optional[str] = None
    raw_content_hash: Optional[str] = None
    actual_tool: Optional[str] = None
    validation_status: str = "unverified"
    sanitization_status: str = "needs_review"
    data_quality_status: str = "reviewing"
    case_evidence: List[str | EvidenceRef] = Field(default_factory=list)
    source_evidence: Optional[str] = None
    proved_at: Optional[str] = None
    proof_evidence: Optional[str] = None
    preconditions: Optional[str] = None
    cve_id: Optional[str] = None
    affected: Optional[str] = None
    version: Optional[int] = None
    cvss: Optional[float] = None
    poc_ref: Optional[str] = None
    usage_count: Optional[int] = 0
    success_rate: Optional[float] = None
    last_used: Optional[str] = None
    disabled: bool = False
    coverage_state: Optional[dict[str, Any]] = None
    confidence: Optional[float] = 0.9
    provenance: dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @field_validator("source_type", mode="before")
    @classmethod
    def normalize_source(cls, value: Any) -> Any:
        if isinstance(value, str):
            return normalize_source_type(value)
        return value

    @field_validator("source_ref", "legacy_source", mode="before")
    @classmethod
    def normalize_source_refs(cls, value: Any) -> Any:
        if isinstance(value, str) and value and value not in NEW_SOURCE_TYPES:
            return value
        return value

    @field_validator("proof_method", mode="before")
    @classmethod
    def normalize_proof_method(cls, value: Any) -> Any:
        if isinstance(value, str) and value.lower() in {"none", "agent", "llm"}:
            return None
        return value

    @field_validator("version", mode="before")
    @classmethod
    def normalize_version(cls, value: Any) -> Any:
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return str(value)

    @field_validator("case_evidence", mode="before")
    @classmethod
    def normalize_evidence(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, (str, dict)):
            value = [value]
        result = []
        for item in value:
            if isinstance(item, EvidenceRef):
                result.append(item)
            elif isinstance(item, dict):
                try:
                    result.append(EvidenceRef(**item))
                except Exception:
                    result.append(str(item.get("evidence_id", "")))
            else:
                result.append(str(item))
        return result

    @model_validator(mode="after")
    def fill_redacted_content(self) -> "KnowledgeEntry":
        if not self.content_redacted:
            self.content_redacted = self.content
        return self


class KBQuery(StrictModel):
    query: str = Field(..., min_length=1)
    types: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    limit: int = Field(default=5, ge=1, le=20)
    include_candidates: bool = False


class KBQueryResult(StrictModel):
    found: bool
    results: List[KnowledgeEntry] = Field(default_factory=list)
    fallback_used: bool = False


class EvidenceRefInput(StrictModel):
    evidence_id: str = Field(..., min_length=1)
    evidence_hash: str = Field(..., min_length=1)


class Candidate(StrictModel):
    source_type: Literal["pentagi", "inhouse"]
    source_id: str = Field(..., min_length=1)
    source_flow: Optional[str] = None
    case_id: str = Field(..., min_length=1)
    entity_id: str = Field(..., min_length=1)
    entity_type: str = "candidate"
    title: str = Field(..., min_length=1)
    technique: str = Field(..., min_length=1)
    content_redacted: str = Field(..., min_length=1)
    content_hash: Optional[str] = None
    actual_tool: str = Field(..., min_length=1)
    evidence_redacted: str = Field(..., min_length=1)
    evidence_id: Optional[str] = None
    evidence_hash: str = Field(..., min_length=1)
    validation_status: Literal["candidate"] = "candidate"
    sanitization_status: Literal["sanitized"] = "sanitized"
    created_at: str = Field(..., min_length=1)
    adapter_version: str = Field(..., min_length=1)
    provenance: dict[str, Any] = Field(default_factory=dict)


class CandidateValidation(StrictModel):
    status: Literal["validated", "quarantined", "rejected"]
    reason_code: str
    reason: str
    evidence_refs: List[EvidenceRefInput] = Field(default_factory=list)
    content_hash: Optional[str] = None


class PromoteRequest(StrictModel):
    source_type: Literal["pentagi", "inhouse"]
    source_id: str = Field(..., min_length=1)
    source_flow: Optional[str] = None
    case_id: str = Field(..., min_length=1)
    entity_id: str = Field(..., min_length=1)
    content_hash: str = Field(..., min_length=1)
    proof_method: Literal["system", "replay", "human"]
    verified: Literal[True]
    note: Optional[str] = None
    case_evidence: List[EvidenceRef] = Field(default_factory=list)


class CaseSnapshotModel(CaseSnapshot):
    pass


CaseRecord = _CaseRecord


class CaseRecordModel(_CaseRecord):
    runtime_id: Optional[str] = None


class CaseRef(StrictModel):
    id: str
    agent: str
    target: str
    model: str
    summary: str
    created_at: str


class GovernanceRecord(StrictModel):
    knowledge_id: str
    status: str
    reason_code: Optional[str] = None
    reason: Optional[str] = None
    content_hash: Optional[str] = None
    source_type: str
    source_id: Optional[str] = None
    source_flow: Optional[str] = None
    quarantined_at: Optional[str] = None
    quarantined_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    audit_json: Optional[str] = None
    created_at: str
    updated_at: str


__all__ = [
    "Candidate",
    "CandidateValidation",
    "CaseRef",
    "CaseRecord",
    "CaseRecordModel",
    "CaseReview",
    "CaseSnapshot",
    "CaseSnapshotModel",
    "EvidenceRef",
    "GovernanceRecord",
    "KBQuery",
    "KBQueryResult",
    "KnowledgeEntry",
    "PromoteRequest",
    "utcnow",
]
