"""FastAPI surface for governed RED-KB operations."""
from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException

from . import store
from .governance import actor_is_admin
from .schemas import CaseRecord, GovernanceRecord, KBQuery, KBQueryResult, KnowledgeEntry, PromoteRequest


app = FastAPI(title="RED-KB", version="3.0")


def _admin_token() -> str:
    return os.environ.get("REDKB_ADMIN_TOKEN", "")


def _bearer_actor(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def _admin_actor(x_actor: str | None) -> str | None:
    if not x_actor:
        return None
    allowlist = [item.strip() for item in os.environ.get("REDKB_ADMIN_ACTORS", "admin,administrator,reviewer").split(",") if item.strip()]
    return x_actor if x_actor in allowlist else None


def _require_governance_actor(x_service_actor: str | None, x_actor: str | None, authorization: str | None) -> str:
    if x_service_actor == "auto_ingest":
        return "auto_ingest"
    token = _bearer_actor(authorization)
    if _admin_token() and token == _admin_token():
        return "admin"
    actor = _admin_actor(x_actor)
    if actor and not _admin_token():
        return actor
    raise HTTPException(status_code=403, detail={"code": "actor-forbidden", "reason": "admin or service actor required"})


def _http_governance_error(exc: store.GovernanceError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail={"code": exc.code, "reason": exc.message, "details": exc.details})


@app.get("/health")
def health():
    return {"status": "ok", "service": "red-kb", "version": "3.0"}


@app.post("/kb/query", response_model=KBQueryResult)
def kb_query(q: KBQuery):
    results = store.query(q.query, types=q.types, tags=q.tags, limit=q.limit,
                          include_candidates=q.include_candidates)
    return KBQueryResult(found=len(results) > 0, results=results)


@app.post("/kb/ingest", response_model=dict)
def kb_ingest(entry: KnowledgeEntry,
              x_service_actor: str | None = Header(default=None),
              x_actor: str | None = Header(default=None),
              authorization: str | None = Header(default=None)):
    actor = _require_governance_actor(x_service_actor, x_actor, authorization)
    try:
        eid = store.ingest(entry)
    except Exception as exc:
        if isinstance(exc, store.GovernanceError):
            raise _http_governance_error(exc) from exc
        raise
    return {"id": eid, "status": "ingested", "tier": "needs_review" if entry.status == "needs_review" else entry.status}


@app.post("/kb/promote/{eid}", response_model=dict)
def kb_promote(eid: str, req: PromoteRequest,
               x_service_actor: str | None = Header(default=None),
               x_actor: str | None = Header(default=None),
               authorization: str | None = Header(default=None)):
    actor = _require_governance_actor(x_service_actor, x_actor, authorization)
    try:
        entry = store.promote(eid, req, actor=actor)
    except store.GovernanceError as exc:
        raise _http_governance_error(exc) from exc
    if not entry:
        raise HTTPException(404, "entry not found")
    return {"id": eid, "status": "promoted", "tier": entry.status,
            "proof_method": entry.proof_method, "verified": entry.verified}


@app.post("/kb/retract/{eid}", response_model=dict)
def kb_retract(eid: str,
               x_service_actor: str | None = Header(default=None),
               x_actor: str | None = Header(default=None),
               authorization: str | None = Header(default=None)):
    actor = _require_governance_actor(x_service_actor, x_actor, authorization)
    try:
        entry = store.retract(eid, actor=actor, reason_code="api-retract")
    except store.GovernanceError as exc:
        raise _http_governance_error(exc) from exc
    if not entry:
        raise HTTPException(404, "entry not found")
    return {"id": eid, "status": entry.status, "verified": entry.verified}


@app.get("/kb/list", response_model=list)
def kb_list():
    return store.list_knowledge()


@app.get("/kb/{eid}", response_model=KnowledgeEntry)
def kb_get(eid: str):
    e = store.get_knowledge(eid)
    if not e:
        raise HTTPException(404, "entry not found")
    return e


@app.get("/kb/governance/{eid}", response_model=GovernanceRecord)
def kb_governance(eid: str,
                  x_actor: str | None = Header(default=None),
                  authorization: str | None = Header(default=None)):
    if not actor_is_admin(_admin_actor(x_actor)) and not (_admin_token() and _bearer_actor(authorization) == _admin_token()):
        raise HTTPException(status_code=403, detail={"code": "actor-forbidden", "reason": "admin actor required"})
    record = store.get_governance(eid, actor="admin")
    if not record:
        raise HTTPException(404, "governance record not found")
    return GovernanceRecord(**record)


@app.get("/coverage/{scope}")
def coverage(scope: str):
    c = store.coverage(scope)
    if not c:
        raise HTTPException(404, "no target_profile for scope")
    return c


@app.post("/cases/submit", response_model=dict)
def case_submit(record: CaseRecord):
    cid = store.submit_case(record)
    return {"id": cid, "status": "stored"}


@app.get("/cases/{cid}")
def case_get(cid: str):
    rec = store.get_case(cid)
    if not rec:
        raise HTTPException(404, "case not found")
    return rec


@app.get("/cases", response_model=list)
def case_list():
    return store.list_cases()
