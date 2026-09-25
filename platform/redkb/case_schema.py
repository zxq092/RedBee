"""Stable case and restricted-evidence contracts used by RED-KB adapters."""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .governance import case_id_for


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class EvidenceRef(StrictModel):
    evidence_id: str = Field(..., min_length=1)
    evidence_hash: str = Field(..., min_length=1)
    kind: str | None = None
    access_level: Literal["restricted", "public"] = "restricted"

    @field_validator("evidence_hash")
    @classmethod
    def valid_hash(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("evidence_hash must be a SHA-256 hex digest")
        return value.lower()


class PhaseSnapshot(StrictModel):
    name: str
    state: str
    started_at: str
    ended_at: str | None = None
    error_code: str | None = None


class FindingSnapshot(StrictModel):
    id: str | int
    status: str
    severity: str
    dedup_key: str


class CoverageSnapshot(StrictModel):
    id: int
    surface: str
    risk_area: str
    outcome: str
    evidence_hash: str


class ToolCallSnapshot(StrictModel):
    name: str
    status: str
    started_at: str
    ended_at: str | None = None
    args_redacted: str
    result_redacted: str


class TrajectorySnapshot(StrictModel):
    tool_calls: list[ToolCallSnapshot] = Field(default_factory=list)
    llm_turns: dict[str, Any] = Field(default_factory=lambda: {"count": 0})
    raw_evidence_ref: list[str] = Field(default_factory=list)


class ProvenanceSnapshot(StrictModel):
    captured_at: str
    adapter_version: str
    raw_size_bytes: int = Field(ge=0)
    sanitized: bool = True


class CaseSnapshot(StrictModel):
    schema_version: Literal[1] = 1
    source_type: Literal["pentagi", "inhouse", "legacy"]
    source_id: str = Field(..., min_length=1)
    source_flow: str | None = None
    legacy_source: str | None = None
    agent: str = Field(..., min_length=1)
    model: str = Field(..., min_length=1)
    runtime_id: str = Field(..., min_length=1)
    task: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    modules: list[str] = Field(default_factory=list)
    phases: list[PhaseSnapshot] = Field(default_factory=list)
    findings: list[FindingSnapshot] = Field(default_factory=list)
    coverage: list[CoverageSnapshot] = Field(default_factory=list)
    trajectory: TrajectorySnapshot = Field(default_factory=TrajectorySnapshot)
    provenance: ProvenanceSnapshot = Field(
        default_factory=lambda: ProvenanceSnapshot(
            captured_at="", adapter_version="unknown", raw_size_bytes=0, sanitized=True
        )
    )

    @model_validator(mode="after")
    def validate_source_contract(self) -> "CaseSnapshot":
        if self.source_type == "inhouse" and self.source_flow is not None:
            raise ValueError("inhouse cases must not set source_flow")
        if self.source_type == "pentagi" and self.source_flow != self.source_id:
            raise ValueError("pentagi source_flow must equal source_id")
        if self.source_type == "legacy" and not self.legacy_source:
            raise ValueError("legacy cases require legacy_source")
        return self

    @property
    def case_id(self) -> str:
        return case_id_for(self.source_type, self.source_id)


class CaseReview(StrictModel):
    source_type: Literal["pentagi", "inhouse", "legacy"]
    source_id: str = Field(..., min_length=1)
    status: Literal["new", "running", "done", "error", "needs_review"]
    reason_code: str | None = None
    target: str | None = None
    details_redacted: dict[str, Any] = Field(default_factory=dict)


class CaseRecord(StrictModel):
    id: str | None = None
    source_type: str | None = None
    source_id: str | None = None
    source_flow: str | None = None
    legacy_source: str | None = None
    agent: str = Field(..., min_length=1)
    model: str = Field(..., min_length=1)
    runtime_id: str | None = None
    task: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    target_id: str | None = None
    trajectory: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    created_at: str | None = None

    @model_validator(mode="after")
    def normalize_legacy_shape(self) -> "CaseRecord":
        if self.source_type is None:
            self.source_type = "legacy"
        if self.source_id is None:
            self.source_id = self.id or self.task
        if self.source_type == "legacy" and not self.legacy_source:
            self.legacy_source = "legacy"
        if self.target_id is None:
            self.target_id = self.target
        return self

    def to_snapshot(self) -> CaseSnapshot:
        return CaseSnapshot(
            source_type=self.source_type or "legacy",
            source_id=self.source_id or self.id or self.task,
            source_flow=self.source_flow,
            legacy_source=self.legacy_source,
            agent=self.agent,
            model=self.model,
            runtime_id=self.runtime_id or "unknown",
            task=self.task,
            target=self.target,
            target_id=self.target_id or self.target,
            trajectory=TrajectorySnapshot.model_validate(self.trajectory),
            provenance=ProvenanceSnapshot(
                captured_at=self.created_at or "",
                adapter_version="legacy",
                raw_size_bytes=len(self.trajectory or ""),
                sanitized=True,
            ),
        )


__all__ = [
    "CaseRecord",
    "CaseReview",
    "CaseSnapshot",
    "CoverageSnapshot",
    "EvidenceRef",
    "FindingSnapshot",
    "PhaseSnapshot",
    "ProvenanceSnapshot",
    "ToolCallSnapshot",
    "TrajectorySnapshot",
]
