"""RED-KB governance, sanitization, hashing, and validation primitives."""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence


NEW_SOURCE_TYPES = frozenset({"pentagi", "inhouse"})
LEGACY_SOURCE_TYPES = frozenset({
    "shannon", "agent-distillation", "llm-expert", "agent", "human", "manual",
    "kb-standard", "open-source-writeup", "network", "replay",
})
GOVERNANCE_STATUSES = frozenset({"active", "quarantined", "disabled", "reviewing", "rejected"})
VALIDATION_STATUSES = frozenset({"unverified", "candidate", "verified", "rejected"})
SANITIZATION_STATUSES = frozenset({"sanitized", "needs_review", "quarantined", "rejected"})
DATA_QUALITY_STATUSES = frozenset({"active", "quarantined", "reviewing", "rejected"})
PROOF_METHODS = frozenset({"system", "replay", "human"})
ACTUAL_TOOLS = frozenset({
    "sqlmap", "curl", "http_request", "web_get_contents", "python", "exec_command",
    "terminal", "nikto", "browser", "nmap", "ffuf", "dirsearch", "gobuster",
    "wfuzz", "nuclei", "whatweb", "xsser", "metasploit", "httpx", "wget",
    "testssl", "sslyze", "openssl", "burp", "commix", "whatweb",
})
RECON_TOOLS = frozenset({"nmap", "web_get_contents", "browser", "nikto", "whatweb"})
FORBIDDEN_TOOL_MARKERS = frozenset({
    "kb_query", "search_answer", "memory", "list_skills", "load_skill", "tool_help",
    "ask_user", "record_coverage", "submit_finding", "create_vulnerability_report",
})
FORBIDDEN_TEXT_MARKERS = ("curl /kb/query", "/kb/query", "toolCallLogs", "tool_calls", "tool-call")
SUCCESS_SIGNALS = (
    "200", "201", "204", "flag", "success", "true", "uid=0", "uid=", "root", "shell",
    "bypass", "authenticated", "access granted", "response difference", "diff",
    "confirmed", "exploit", "sqli", "xss", "ssrf", "idor", "upload",
)

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])")
_COOKIE_RE = re.compile(r"(?i)\b(?:cookie|session(?:_id)?|jwt)\s*[:=]\s*[^;\s,]+")
_AUTH_RE = re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+\S+")
_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token)\s*[:=]\s*[^;\s,]+"
)
_HASH_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{16,64}(?![0-9a-f])")


@dataclass(frozen=True)
class SanitizationResult:
    content: str
    sanitized: bool
    status: str
    reason_codes: tuple[str, ...] = ()
    raw_content_hash: str | None = None
    redacted_content_hash: str | None = None

    @property
    def reason_code(self) -> str | None:
        return self.reason_codes[0] if self.reason_codes else None


@dataclass(frozen=True)
class ValidationResult:
    status: str
    reason_code: str
    reason: str
    evidence_refs: tuple[dict[str, str], ...] = ()
    content_hash: str | None = None


@dataclass(frozen=True)
class GovernanceTransition:
    before: str
    after: str
    actor: str
    reason_code: str
    reason: str
    batch_id: str | None = None


GOVERNANCE_TRANSITIONS = {
    "active": frozenset({"reviewing", "quarantined", "disabled", "rejected"}),
    "quarantined": frozenset({"reviewing", "disabled", "rejected"}),
    "disabled": frozenset({"reviewing", "active", "rejected"}),
    "reviewing": frozenset({"active", "quarantined", "disabled", "rejected"}),
    "rejected": frozenset({"reviewing", "active", "quarantined", "disabled"}),
}


def canonical_json(value: Any) -> str:
    if isinstance(value, str):
        value = unicodedata.normalize("NFC", value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def hash_text(value: Any) -> str:
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def case_id_for(source_type: str, source_id: str) -> str:
    payload = canonical_json({"source_type": source_type, "source_id": source_id})
    return f"case-{hash_text(payload)[:16]}"


def deterministic_entity_id(case_id: str, entity_type: str, content_hash: str) -> str:
    payload = canonical_json({"case_id": case_id, "entity_type": entity_type, "content_hash": content_hash})
    return f"entity-{hash_text(payload)[:16]}"


def normalize_source_type(source_type: str | None, legacy_source: str | None = None) -> str:
    source_type = source_type or "legacy"
    if source_type in NEW_SOURCE_TYPES:
        return source_type
    if source_type in LEGACY_SOURCE_TYPES or source_type not in NEW_SOURCE_TYPES:
        return "legacy"
    return "legacy"


def normalize_source_tuple(source_type: str | None, legacy_source: str | None = None) -> tuple[str, str | None]:
    source_type = source_type or "legacy"
    if source_type in NEW_SOURCE_TYPES:
        return source_type, legacy_source
    if legacy_source and source_type == "legacy":
        return "legacy", legacy_source
    return "legacy", source_type


def sanitize_text(value: Any) -> SanitizationResult:
    raw = value if isinstance(value, str) else canonical_json(value)
    raw = unicodedata.normalize("NFC", raw)
    content = raw
    reasons: list[str] = []

    lowered = content.lower()
    if any(marker in lowered for marker in FORBIDDEN_TEXT_MARKERS):
        content = re.sub(r"(?i)(curl\s+.*?/kb/query.*)", "<forbidden-command>", content)
        content = re.sub(r"/kb/query", "<kb-query>", content)
        reasons.append("kb-query-command")
        status = "quarantined"
    else:
        status = "sanitized"

    content = _COOKIE_RE.sub("<cookie>", content)
    content = _AUTH_RE.sub("<authorization>", content)
    content = _CREDENTIAL_RE.sub("<credential>", content)
    content = _HASH_RE.sub("<hash>", content)
    content = _IP_RE.sub("<target>", content)
    content = _URL_RE.sub("<url>", content)

    if reasons:
        sanitized = False
    else:
        sanitized = bool(content == raw)
        if not sanitized:
            reasons.append("sensitive-data")
            status = "needs_review"

    return SanitizationResult(
        content=content,
        sanitized=sanitized,
        status=status,
        reason_codes=tuple(dict.fromkeys(reasons)),
        raw_content_hash=hash_text(raw),
        redacted_content_hash=hash_text(content),
    )


def is_sensitive_text(value: Any) -> bool:
    return not sanitize_text(value).sanitized


def _entry_get(entry: Any, name: str, default: Any = None) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name, default)
    return getattr(entry, name, default)


def _entry_status(entry: Any) -> str:
    return str(_entry_get(entry, "status", "")).lower()


def governance_status_for_entry(entry: Any) -> str:
    source_type = str(_entry_get(entry, "source_type", "")).lower()
    data_quality = str(_entry_get(entry, "data_quality_status", "")).lower()
    sanitization = str(_entry_get(entry, "sanitization_status", "")).lower()
    validation = str(_entry_get(entry, "validation_status", "")).lower()
    status = _entry_status(entry)
    content_hash = _entry_get(entry, "redacted_content_hash") or _entry_get(entry, "content_hash")

    if source_type not in NEW_SOURCE_TYPES or data_quality in {"quarantined", "rejected"}:
        return "quarantined" if data_quality == "quarantined" else "reviewing"
    if sanitization in {"quarantined", "rejected"}:
        return "quarantined"
    if sanitization != "sanitized" or validation not in {"candidate", "verified"} or not content_hash:
        return "reviewing"
    if status in {"quarantined", "rejected", "disabled"}:
        return status
    if status == "authoritative" and not bool(_entry_get(entry, "verified", False)):
        return "reviewing"
    return "active"


def governance_allowed(entry: Any) -> bool:
    return governance_status_for_entry(entry) == "active"


def filter_governance(entries: Iterable[Any], include_candidates: bool = False) -> list[Any]:
    allowed = []
    for entry in entries:
        if governance_status_for_entry(entry) != "active":
            continue
        if not include_candidates and _entry_status(entry) == "candidate":
            continue
        if str(_entry_get(entry, "type", "")) == "target_profile":
            continue
        allowed.append(entry)
    return allowed


def _candidate_text(candidate: Any) -> str:
    return str(_entry_get(candidate, "content_redacted", _entry_get(candidate, "content", "")) or "")


def _evidence_map(evidence: Any) -> dict[str, Any]:
    if evidence is None:
        return {}
    if isinstance(evidence, Mapping):
        if _entry_get(evidence, "evidence_id", None) and _entry_get(evidence, "evidence_hash", None):
            return {str(_entry_get(evidence, "evidence_id", "")): evidence}
        result = {}
        for key, item in evidence.items():
            item_id = str(_entry_get(item, "evidence_id", key))
            if item_id:
                result[item_id] = item
        return result
    result = {}
    for item in evidence or []:
        if isinstance(item, Mapping):
            key = str(_entry_get(item, "evidence_id", ""))
            if key:
                result[key] = item
    return result


def _success_signal(text: str) -> bool:
    lowered = text.lower()
    return any(signal in lowered for signal in SUCCESS_SIGNALS)


def validate_candidate(candidate: Any, case: Any, restricted_evidence: Any) -> ValidationResult:
    source_type = str(_entry_get(candidate, "source_type", ""))
    case_source_type = str(_entry_get(case, "source_type", ""))
    if source_type not in NEW_SOURCE_TYPES:
        return ValidationResult("rejected", "source-type-invalid", "candidate source must be pentagi or inhouse")
    if source_type != case_source_type:
        return ValidationResult("rejected", "source-mismatch", "candidate and case source_type do not match")
    if str(_entry_get(candidate, "source_id", "")) != str(_entry_get(case, "source_id", "")):
        return ValidationResult("rejected", "source-id-mismatch", "candidate and case source_id do not match")
    if str(_entry_get(candidate, "source_flow", None)) != str(_entry_get(case, "source_flow", None)):
        return ValidationResult("rejected", "source-flow-mismatch", "candidate and case source_flow do not match")
    if str(_entry_get(candidate, "case_id", "")) != str(_entry_get(case, "case_id", "")):
        return ValidationResult("rejected", "case-mismatch", "candidate and case identity do not match")

    entity_id = _entry_get(candidate, "entity_id")
    entity_type = str(_entry_get(candidate, "entity_type", "candidate"))
    content_hash = _entry_get(candidate, "content_hash") or _entry_get(candidate, "redacted_content_hash")
    redacted_hash = _entry_get(candidate, "redacted_content_hash")
    if entity_id and str(entity_id) != deterministic_entity_id(str(_entry_get(case, "case_id", "")), entity_type, str(content_hash or "")):
        return ValidationResult("rejected", "entity-id-mismatch", "candidate entity_id is not deterministic")
    if not content_hash:
        return ValidationResult("quarantined", "content-hash-missing", "candidate content hash is required")

    content_redacted = _candidate_text(candidate)
    if not content_redacted:
        return ValidationResult("quarantined", "content-empty", "candidate content is empty")
    content_check = sanitize_text(content_redacted)
    if not content_check.sanitized:
        return ValidationResult("quarantined", "sensitive-content", "candidate content failed sanitization")
    if redacted_hash and str(redacted_hash) != hash_text(content_redacted):
        return ValidationResult("quarantined", "redacted-hash-mismatch", "redacted content hash does not match")

    actual_tool = str(_entry_get(candidate, "actual_tool", "")).lower()
    if not actual_tool:
        return ValidationResult("quarantined", "actual-tool-missing", "actual_tool is required")
    if actual_tool in FORBIDDEN_TOOL_MARKERS:
        return ValidationResult("quarantined", "forbidden-tool", "retrieval and coordination tools cannot prove a vulnerability")
    if actual_tool not in ACTUAL_TOOLS:
        return ValidationResult("quarantined", "actual-tool-invalid", "actual_tool is not an allowed validation tool")
    if actual_tool in RECON_TOOLS:
        return ValidationResult("quarantined", "recon-only", "reconnaissance tools cannot independently prove a vulnerability")

    evidence_hash = _entry_get(candidate, "evidence_hash")
    evidence_redacted = str(_entry_get(candidate, "evidence_redacted", "") or "")
    if not evidence_hash or not evidence_redacted:
        return ValidationResult("quarantined", "evidence-missing", "redacted evidence and evidence hash are required")
    evidence_check = sanitize_text(evidence_redacted)
    if not evidence_check.sanitized or not _success_signal(evidence_redacted):
        return ValidationResult("quarantined", "evidence-insufficient", "evidence must be sanitized and contain a success signal")
    evidence_by_id = _evidence_map(restricted_evidence)
    evidence_item = evidence_by_id.get(str(_entry_get(candidate, "evidence_id", "")))
    if evidence_item is None:
        return ValidationResult("quarantined", "evidence-ref-missing", "candidate evidence is not present in restricted evidence")
    if str(_entry_get(evidence_item, "evidence_hash", "")) != str(evidence_hash):
        return ValidationResult("quarantined", "evidence-hash-mismatch", "candidate and restricted evidence hashes do not match")

    validation_status = str(_entry_get(candidate, "validation_status", "")).lower()
    if validation_status != "candidate":
        return ValidationResult("rejected", "validation-status-invalid", "candidate must be in candidate validation state")
    if str(_entry_get(candidate, "sanitization_status", "")).lower() != "sanitized":
        return ValidationResult("quarantined", "sanitization-status-invalid", "candidate sanitization status must be sanitized")
    if not _entry_get(candidate, "created_at"):
        return ValidationResult("quarantined", "timestamp-missing", "candidate created_at is required")

    target = str(_entry_get(case, "target", ""))
    if target and target in content_redacted:
        return ValidationResult("quarantined", "target-specific-content", "candidate content contains target-specific material")

    refs = tuple({
        "evidence_id": str(_entry_get(item, "evidence_id", "")),
        "evidence_hash": str(_entry_get(item, "evidence_hash", "")),
    } for item in evidence_by_id.values() if _entry_get(item, "evidence_id"))
    return ValidationResult(
        status="validated",
        reason_code="validated",
        reason="candidate passed governance checks",
        evidence_refs=refs,
        content_hash=str(content_hash),
    )


def transition_governance(before: str, after: str, actor: str, reason_code: str, reason: str, batch_id: str | None = None) -> GovernanceTransition:
    before = before or "reviewing"
    after = after or "reviewing"
    if after not in GOVERNANCE_TRANSITIONS.get(before, frozenset()):
        raise ValueError(f"invalid governance transition {before} -> {after}")
    return GovernanceTransition(before, after, actor, reason_code, reason, batch_id)


def actor_is_service(actor: str | None) -> bool:
    return actor == "auto_ingest"


def actor_is_admin(actor: str | None, allowlist: Sequence[str] | None = None) -> bool:
    if not actor:
        return False
    if allowlist is None:
        return actor in {"admin", "administrator", "reviewer"}
    return actor in set(allowlist)


__all__ = [
    "ACTUAL_TOOLS",
    "GOVERNANCE_STATUSES",
    "GOVERNANCE_TRANSITIONS",
    "NEW_SOURCE_TYPES",
    "PROOF_METHODS",
    "SanitizationResult",
    "ValidationResult",
    "actor_is_admin",
    "actor_is_service",
    "case_id_for",
    "canonical_json",
    "deterministic_entity_id",
    "filter_governance",
    "governance_allowed",
    "governance_status_for_entry",
    "hash_text",
    "is_sensitive_text",
    "normalize_source_type",
    "sanitize_text",
    "transition_governance",
    "validate_candidate",
]
