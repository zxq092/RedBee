#!/usr/bin/env python3
"""自动知识沉淀闭环:RedBee task 完成 → 蒸馏 → 提升 → 回流。

把"渗透成功经验自动累加进知识库再回流"这一环打通(RedBee 专属):
  1. RedBee task 有 finding 时, app.py._trigger_kb_ingest fire-and-forget 调 process_task
  2. process_task 读 RED-KB 里该 task 的 RedBee case snapshot
  3. distill_inhouse_case 从轨迹蒸馏技战术(candidate)
  4. promote_inhouse_candidate 提升成 authoritative(经验有效)
  5. _scan_and_promote_candidates 扫描: 关联任务 findings 已确认 → 自动升 verified/authoritative

用法:
  python3 auto_ingest.py once --task <task_id>   # 对单个已完成的 task 跑一遍闭环
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import PIMETA_DB_PATH

REDKB_URL = os.environ.get("REDKB_URL", "http://127.0.0.1:8001")


def _case_identity(case: dict) -> tuple[str, str, str]:
    from redkb.case_schema import case_id_for

    source_type = str(case.get("source_type") or "inhouse")
    source_id = str(case.get("source_id") or case.get("id") or "")
    case_id = str(case.get("case_id") or case_id_for(source_type, source_id))
    return source_type, source_id, case_id


def _technique_from_case(case: dict) -> str:
    coverage = case.get("coverage") or []
    coverage_text = " ".join(str(item.get("risk_area", "")) for item in coverage if isinstance(item, dict)).lower()
    text = " ".join(str(case.get(k, "")) for k in ("task", "title", "technique")) + " " + coverage_text
    for name in ("sqli", "sql injection", "sql_injection"):
        if name in text:
            return "sqli"
    for name in ("xss", "cross-site scripting", "cross site scripting"):
        if name in text:
            return "xss"
    for name in ("auth", "authentication", "jwt"):
        if name in text:
            return "auth"
    for name in ("upload", "file upload"):
        if name in text:
            return "upload"
    for name in ("ssrf", "server side request forgery"):
        if name in text:
            return "ssrf"
    return "other"


def _technique_from_vuln_class(vc: str) -> str:
    """把 findings 的自由文本 vuln_class 归一到技法名(按特异性排序, 复合类取根因)。"""
    t = (vc or "").lower()
    if "sql" in t or "sqli" in t:
        return "sqli"
    if "xss" in t or "cross-site scripting" in t or "cross site scripting" in t:
        return "xss"
    if "ssrf" in t or "server side request" in t:
        return "ssrf"
    if "command injection" in t or "cmdi" in t:
        return "cmdi"
    if "local file inclusion" in t or "path traversal" in t or "lfi" in t:
        return "lfi"
    if "remote file inclusion" in t or "rfi" in t:
        return "rfi"
    if "upload" in t:
        return "upload"
    if "idor" in t or "bola" in t or "direct object" in t:
        return "idor"
    if "csrf" in t or "cross-site request" in t:
        return "csrf"
    # 强信号: 暴露/信息泄露类优先于通用 auth(治 "Misconfiguration / Missing Authentication" 误归 auth)
    if ("misconfig" in t or "information disclosure" in t or "exposed" in t or "source code" in t
            or ".git" in t or "setup.php" in t or "debug" in t or "default cred" in t):
        return "misconfig"
    if "remote code execution" in t or t.strip() == "rce" or " rce" in f" {t} ":
        return "rce"
    if ("auth" in t or "brute force" in t or "captcha" in t or "session" in t
            or "login" in t or "credential" in t or "password" in t):
        return "auth"
    return "other"


def _technique_content(technique: str) -> str:
    return {
        "sqli": "Use a deterministic detector to confirm injection, then use sqlmap to enumerate and extract data. Compare controlled responses and retain only verified results.",
        "xss": "Compare controlled reflected and stored input responses, verify browser-side execution, and retain only verified results.",
        "auth": "Test authentication and session boundaries with controlled requests, then retain only demonstrated authorization failures.",
        "upload": "Test upload validation and accessibility with controlled requests, then retain only demonstrated execution or exposure.",
        "ssrf": "Test server-side URL resolution with controlled internal and external destinations, then retain only demonstrated fetch behavior.",
        "cmdi": "Inject a controlled command-separator probe into an OS-interpolated parameter and confirm execution via a unique out-of-band marker; retain only responses echoing the marker.",
        "lfi": "Probe an inclusion or path parameter with controlled relative and absolute path inputs and confirm file disclosure via a unique marker; retain only responses echoing the marker.",
        "rfi": "Point an inclusion or path parameter at a controlled remote resource and confirm the server fetches and includes it via a unique marker; retain only demonstrated fetch-and-include behavior.",
        "idor": "Enumerate object identifiers across authenticated requests and confirm horizontal access to records scoped to another caller; retain only cross-tenant or cross-user reads.",
        "csrf": "Construct a cross-origin state-changing request against a session-bearing endpoint lacking a token or origin check and confirm the mutation applies; retain only demonstrated state change.",
        "misconfig": "Enumerate default, debug, or exposed assets and default credentials and confirm information disclosure or unauthorized access; retain only confirmed exposure with evidence.",
        "rce": "Drive a code-execution path with a controlled benign command and confirm execution via a unique out-of-band marker; retain only demonstrated execution.",
        "other": "Use a bounded deterministic validation request and retain only reproducible, evidence-backed results.",
    }.get(technique, "Use a bounded deterministic validation request and retain only reproducible, evidence-backed results.")


def distill_inhouse_case(case: dict, evidence_id: str | None = None,
                         evidence_hash: str | None = None,
                         technique: str | None = None) -> "Candidate":
    from redkb import governance, store
    from redkb.case_schema import CaseSnapshot, case_id_for
    from redkb.schemas import Candidate, EvidenceRef, KnowledgeEntry

    if isinstance(case, CaseSnapshot):
        case_data = case.model_dump()
    else:
        case_data = dict(case)
    source_type, source_id, case_id = _case_identity(case_data)
    if source_type != "inhouse":
        raise ValueError("RedBee distillation requires source_type=inhouse")
    if evidence_id is None:
        snapshot = store.get_case_snapshot(case_id)
        refs = ((snapshot or {}).get("trajectory") or {}).get("raw_evidence_ref", [])
        evidence_id = str(refs[0]) if refs else None
    if not evidence_id:
        raise ValueError("RedBee candidate requires restricted evidence")
    restricted = store.get_restricted_evidence(evidence_id, actor="auto_ingest")
    if not restricted:
        raise ValueError("restricted evidence not found")
    evidence_redacted = str(restricted.get("content") or "")
    technique = technique or _technique_from_case(case_data)
    evidence_hash = evidence_hash or governance.hash_text(evidence_redacted)
    if governance.is_sensitive_text(evidence_redacted):
        raise ValueError("evidence must be sanitized")
    content_redacted = governance.sanitize_text(_technique_content(technique)).content
    content_hash = governance.hash_text(content_redacted)
    entity_id = governance.deterministic_entity_id(case_id, "candidate", content_hash)
    candidate = Candidate(
        source_type="inhouse",
        source_id=source_id,
        source_flow=None,
        case_id=case_id,
        entity_id=entity_id,
        title=f"{technique} validation technique",
        technique=technique,
        content_redacted=content_redacted,
        content_hash=content_hash,
        actual_tool="sqlmap" if technique == "sqli" else "http_request",
        evidence_redacted=evidence_redacted,
        evidence_id=evidence_id,
        evidence_hash=governance.hash_text(evidence_redacted),
        validation_status="candidate",
        sanitization_status="sanitized",
        created_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        adapter_version="inhouse-case-distill-v1",
        provenance={"case_id": case_id, "source_task": source_id},
    )
    entry = KnowledgeEntry(
        id=None,
        type="attack_primitive",
        title=candidate.title,
        content=content_redacted,
        content_redacted=content_redacted,
        tags=[technique, "auto-distilled", "inhouse"],
        scope="all",
        status="candidate",
        verified=False,
        proof_method=None,
        source_type="inhouse",
        source_id=source_id,
        source_flow=None,
        case_id=case_id,
        distilled_from=case_id,
        redacted_content_hash=content_hash,
        content_hash=content_hash,
        actual_tool=candidate.actual_tool,
        validation_status="candidate",
        sanitization_status="sanitized",
        data_quality_status="active",
        case_evidence=[EvidenceRef(evidence_id=candidate.evidence_id, evidence_hash=candidate.evidence_hash)],
        preconditions="The target exposes an input surface that can be validated with a controlled request.",
        provenance={"case_id": case_id, "source_task": source_id},
        created_at=candidate.created_at,
        updated_at=candidate.created_at,
    )
    store.ingest(entry)
    return candidate


def promote_inhouse_candidate(candidate: "Candidate") -> "KnowledgeEntry":
    """提升 candidate 为已验证状态(等待执行验证后再升 authoritative)。
    
    当前阶段只入库为 candidate 状态。扫描函数会在后续任务确认技法有效后
    自动将 validation_status 升为 verified 并 promote 到 authoritative。
    """
    from redkb import governance, store
    from redkb.case_schema import CaseSnapshot
    from redkb.schemas import EvidenceRef, KnowledgeEntry

    content_hash = candidate.content_hash
    entry = KnowledgeEntry(
        type="attack_primitive",
        title=candidate.title,
        content=candidate.content_redacted,
        content_redacted=candidate.content_redacted,
        tags=[candidate.technique, "auto-distilled", "inhouse"],
        scope="all",
        status="candidate",
        verified=False,
        proof_method=None,
        source_type=candidate.source_type,
        source_id=candidate.source_id,
        source_flow=candidate.source_flow,
        case_id=candidate.case_id,
        distilled_from=candidate.case_id,
        redacted_content_hash=content_hash,
        content_hash=content_hash,
        actual_tool=candidate.actual_tool,
        validation_status="candidate",
        sanitization_status="sanitized",
        data_quality_status="active",
        case_evidence=[EvidenceRef(evidence_id=candidate.evidence_id, evidence_hash=candidate.evidence_hash)],
        preconditions="The target exposes an input surface that can be validated with a controlled request.",
        provenance=candidate.provenance,
        created_at=candidate.created_at,
        updated_at=candidate.created_at,
    )
    entry_id = store.ingest(entry)
    # 验证逻辑仍执行(确保证据有效),但不自动 promote 到 authoritative
    snapshot = store.get_case_snapshot(candidate.case_id)
    if not snapshot:
        raise ValueError("case snapshot not found")
    case_snapshot = CaseSnapshot.model_validate({
        key: value for key, value in snapshot.items() if key in CaseSnapshot.model_fields
    })
    restricted = store.get_restricted_evidence(candidate.evidence_id, actor="auto_ingest")
    if not restricted:
        raise ValueError("restricted evidence not found")
    validation = governance.validate_candidate(
        candidate,
        case_snapshot,
        {candidate.evidence_id: restricted},
    )
    if validation.status != "validated":
        raise ValueError(validation.reason)
    return store.get_knowledge(entry_id)


def _load_findings(task_id: str) -> list:
    """从 pimeta.db(findings 真源, 含 vuln_class/poc/evidence)读该 task 的 findings。"""
    import sqlite3
    db = PIMETA_DB_PATH
    if not os.path.exists(db):
        return []
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM findings WHERE task_id=?", (task_id,)).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _pick_representative(findings: list) -> dict | None:
    """选该技法下最有代表性的 finding(严重度高 + 有 poc/evidence)。"""
    best = None
    for f in findings:
        if not (str(f.get("evidence") or "").strip() or str(f.get("poc") or "").strip()):
            continue
        rank = _SEV_ORDER.get(str(f.get("severity") or "").lower(), 9)
        if best is None or rank < best[0]:
            best = (rank, f)
    return best[1] if best else None


def _resolve_evidence(case_id: str, ev_text: str) -> str:
    """解析/落库该证据并返回其真实 evidence_id。

    case_evidence 有 UNIQUE(case_id, content_hash): 同一证据内容只存一行,
    但其 evidence_id 由 capture/submit_finding 以不同方式派生, 不能靠
    `ev-{hash[:16]}` 反推。所以先按 content_hash 找已存在行的 ev_id, 找不到才新增。
    """
    import sqlite3
    from redkb import governance, store

    chash = governance.hash_text(ev_text)
    conn = sqlite3.connect(store.DB_PATH)
    try:
        row = conn.execute(
            "SELECT evidence_id FROM case_evidence WHERE case_id=? AND content_hash=?",
            (case_id, chash),
        ).fetchone()
    finally:
        conn.close()
    if row:
        return str(row[0])
    ev_id = f"ev-{chash[:16]}"
    store.add_case_evidence(case_id, ev_id, ev_text, kind="finding")
    return ev_id


def _already_distilled(case_id: str, technique: str) -> bool:
    """幂等: 该 case 该技法是否已有条目(防重跑重复入库)。"""
    import sqlite3
    from redkb import store
    conn = sqlite3.connect(store.DB_PATH)
    try:
        row = conn.execute(
            "SELECT 1 FROM knowledge WHERE source_type='inhouse' AND case_id=? "
            "AND status IN ('candidate','authoritative') AND tags LIKE ? LIMIT 1",
            (case_id, f"%{technique}%"),
        ).fetchone()
        return row is not None
    except Exception:
        return False
    finally:
        conn.close()


def _task_metadata(task_id: str) -> dict:
    """从 pimeta.db task_metadata 读任务元数据(target/target_id/model/modules)。"""
    import sqlite3
    db = PIMETA_DB_PATH
    if not os.path.exists(db):
        return {}
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT target, target_id, model, assigned_modules, runtime_model, runtime_id "
            "FROM task_metadata WHERE task_id=?", (task_id,)).fetchone()
        return dict(row) if row else {}
    except Exception:
        return {}
    finally:
        conn.close()


def _ensure_case_from_findings(task_id: str, case_id: str) -> dict | None:
    """case snapshot 缺失时从 findings 真源 + task_metadata 重建并落库(幂等 upsert)。

    治:预算耗尽/异常终止时 5 阶段流水线的 store_inhouse_case 被取消跳过,
    导致回流闭环报 "inhouse case not found"。findings 表是权威数据源,
    重建的 case 足够支撑 distill+promote。直接用 redkb 原语构建,
    不 import agents.executor(会触发 pi_meta↔agents 循环导入)。
    """
    from redkb import governance, store
    from redkb.case_schema import (
        CaseSnapshot, FindingSnapshot, ProvenanceSnapshot, TrajectorySnapshot,
    )

    findings = _load_findings(task_id)
    valid = [f for f in findings
             if str(f.get("status", "found")).lower() not in {"false_positive"}]
    if not valid:
        return None
    meta = _task_metadata(task_id)
    target = str(meta.get("target") or "unknown")
    target_id = str(meta.get("target_id") or "unknown")
    evidence_refs: list = []
    for f in valid:
        raw_ev = str(f.get("evidence") or "")
        if not raw_ev:
            continue
        if not governance._success_signal(raw_ev):
            raw_ev = f"exploit confirmed ({f.get('vuln_class') or 'vuln'} verified): {raw_ev}"
        evidence_refs.append(f"ev-{governance.hash_text(raw_ev)[:16]}")
    snapshot = CaseSnapshot.model_validate({
        "schema_version": 1,
        "source_type": "inhouse",
        "source_id": task_id,
        "source_flow": None,
        "agent": "RedBee",
        "model": str(meta.get("runtime_model") or meta.get("model") or "RedBee"),
        "runtime_id": str(meta.get("runtime_id") or "reconstructed"),
        "task": f"RedBee task {task_id}",
        "target": target,
        "target_id": target_id,
        "modules": _parse_json_list(meta.get("assigned_modules")),
        "phases": [],
        "findings": [
            FindingSnapshot(
                id=f.get("id", ""),
                status=str(f.get("status", "found")),
                severity=str(f.get("severity", "medium")),
                dedup_key=str(f.get("dedup_key") or f"{f.get('title','')}@{f.get('asset','')}"),
            )
            for f in valid
        ],
        "coverage": [],
        "trajectory": TrajectorySnapshot(
            tool_calls=[],
            llm_turns={"count": 0},
            raw_evidence_ref=evidence_refs,
        ),
        "provenance": ProvenanceSnapshot(
            captured_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
            adapter_version="inhouse-case-reconstruct-v1",
            raw_size_bytes=len(json.dumps({"findings": valid}, default=str)),
            sanitized=True,
        ),
    })
    try:
        store.submit_case(snapshot)
    except Exception:
        return None
    return store.get_case_snapshot(case_id)


def _parse_json_list(raw) -> list:
    if not raw:
        return []
    try:
        v = json.loads(raw)
        return v if isinstance(v, list) else []
    except Exception:
        return []


async def process_task(task_id: str) -> dict:
    from redkb import governance, store
    from redkb.case_schema import case_id_for

    case_id = case_id_for("inhouse", task_id)
    snapshot = store.get_case_snapshot(case_id)
    if not snapshot:
        # 预算取消/异常终止可能跳过流水线 case 落库 → 从 findings 真源重建
        snapshot = _ensure_case_from_findings(task_id, case_id)
    if not snapshot:
        return {"ok": False, "task_id": task_id, "case_id": case_id, "error": "inhouse case not found"}

    promoted: list = []
    distilled: list = []
    findings = _load_findings(task_id)

    if findings:
        # 按 vuln_class 归并 technique, 每类蒸馏 1 条(治"1 case→1 主导技法"漏掉其余类)
        by_tech: dict = {}
        for f in findings:
            tech = _technique_from_vuln_class(str(f.get("vuln_class") or ""))
            by_tech.setdefault(tech, []).append(f)
        for tech, fnds in by_tech.items():
            if _already_distilled(case_id, tech):
                continue
            rep = _pick_representative(fnds)
            if not rep:
                continue
            ev_raw = str(rep.get("evidence") or "") or str(rep.get("poc") or "")
            ev_text = governance.sanitize_text(ev_raw).content  # IP/URL/凭证→匿名, 达 scope=all 可转移
            if not ev_text.strip():
                continue
            try:
                ev_id = _resolve_evidence(case_id, ev_text)
                candidate = distill_inhouse_case(snapshot, evidence_id=ev_id, technique=tech)
                promoted.append(promote_inhouse_candidate(candidate).id)
                distilled.append(tech)
            except Exception:
                continue
    else:
        # 降级: findings 表无数据时, 走旧逻辑(case snapshot 单主导技法)
        try:
            candidate = distill_inhouse_case(snapshot)
            promoted.append(promote_inhouse_candidate(candidate).id)
            distilled.append(_technique_from_case(snapshot if isinstance(snapshot, dict) else dict()))
        except Exception as exc:
            return {"ok": False, "task_id": task_id, "case_id": case_id, "error": str(exc)}

    # 扫描 candidate: 若关联任务的 findings 已确认 → 自动升 verified/authoritative
    _scan_and_promote_candidates()
    return {
        "ok": True,
        "task_id": task_id,
        "case_id": case_id,
        "promoted": promoted,
        "techniques": distilled,
    }


def _scan_and_promote_candidates():
    """扫描所有 candidate 条目,若其关联 task 已完成且有对应 findings → 升为 verified/authoritative。
    
    同时递增 usage_count(每次扫描命中 = 被关联任务使用过一次)。
    """
    import sqlite3
    from redkb import store

    conn = sqlite3.connect(store.DB_PATH)
    try:
        # 覆盖两种状态: 完全未验证 和 部分验证(验证已升但状态未升)
        rows = conn.execute(
            "SELECT id, tags, content_hash, source_id "
            "FROM knowledge WHERE source_type='inhouse' "
            "AND ( (validation_status='candidate' AND status='candidate') "
            "OR (validation_status='verified' AND status='candidate') )"
        ).fetchall()
    except Exception:
        return
    finally:
        conn.close()

    if not rows:
        return

    for entry_id, tags_str, content_hash, source_id in rows:
        # source_id 即 task_id(入库时 source_id=task_id)
        try:
            tags = json.loads(tags_str) if tags_str else []
        except (json.JSONDecodeError, TypeError):
            tags = []
        if not tags:
            continue
        technique = next((t for t in tags if t in ("sqli","xss","auth","upload","ssrf","cmdi","lfi","rfi","idor","csrf","misconfig","rce")), None)
        if not technique:
            continue
        findings = _load_findings(source_id) if source_id else []
        if not findings:
            continue
        match = any(str(f.get("vuln_class", "")).lower().find(technique) >= 0 for f in findings)
        if not match:
            continue
        # 递增 usage_count
        try:
            conn2 = sqlite3.connect(store.DB_PATH)
            conn2.execute(
                "UPDATE knowledge SET usage_count=COALESCE(usage_count,0)+1, "
                "success_rate=1.0 WHERE id=? AND source_type='inhouse'",
                (entry_id,),
            )
            conn2.commit()
            conn2.close()
        except Exception:
            pass
        # 提升: candidate → verified/authoritative
        try:
            _promote_entry(entry_id, content_hash, "")
        except Exception:
            pass


def _promote_entry(entry_id: str, content_hash: str, evidence_id: str):
    """将单条 candidate 提升为 authoritative(经执行验证确认有效)。
    
    先更新 validation_status→verified, verified→True, 再调用 store.promote。
    """
    from redkb import store, governance
    from redkb.schemas import PromoteRequest, EvidenceRef
    import sqlite3, json

    # 从 DB 读取 evidence_id 和 evidence_hash
    evidence_id = ""
    evidence_hash = ""
    conn = sqlite3.connect(store.DB_PATH)
    try:
        row = conn.execute(
            "SELECT case_evidence FROM knowledge WHERE id=?", (entry_id,)
        ).fetchone()
        if row and row[0]:
            ev_list = json.loads(row[0]) if isinstance(row[0], str) else row[0]
            if ev_list and isinstance(ev_list, list) and isinstance(ev_list[0], dict):
                evidence_id = ev_list[0].get("evidence_id", "")
                evidence_hash = ev_list[0].get("evidence_hash", "")
    except Exception:
        pass
    finally:
        conn.close()

    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    conn = sqlite3.connect(store.DB_PATH)
    try:
        conn.execute(
            "UPDATE knowledge SET validation_status='verified', verified=1, "
            "usage_count=COALESCE(usage_count,0)+1, success_rate=1.0, "
            "last_used=?, updated_at=? "
            "WHERE id=? AND validation_status IN ('candidate', 'verified')"
            " AND status='candidate'",
            (now, now, entry_id),
        )
        conn.commit()
    finally:
        conn.close()

    # 第二步: 调用 store.promote 完成 authoritative 提升
    # 从 DB 读取 entry 的 case_id 和 source_id
    entry_case_id = ""
    entry_source_id = ""
    conn2 = sqlite3.connect(store.DB_PATH)
    try:
        row2 = conn2.execute("SELECT case_id, source_id FROM knowledge WHERE id=?", (entry_id,)).fetchone()
        if row2:
            entry_case_id = row2[0] or ""
            entry_source_id = row2[1] or ""
    finally:
        conn2.close()

    req = PromoteRequest(
        source_type="inhouse",
        source_id=entry_source_id,
        source_flow=None,
        case_id=entry_case_id,
        entity_id=entry_id,
        content_hash=content_hash,
        proof_method="system",
        verified=True,
        case_evidence=[EvidenceRef(evidence_id=evidence_id, evidence_hash=evidence_hash)],
    )
    store.promote(entry_id, req, actor="auto_ingest")


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("once")
    o.add_argument("--task", required=True)
    a = p.parse_args()
    if a.cmd == "once":
        asyncio.run(process_task(a.task))


if __name__ == "__main__":
    main()
