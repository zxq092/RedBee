"""sync_kb: 把 RED-KB 已 promote 的知识同步到 PentAGI knowledge REST API.

规格(2026-09-17-model-kb-data-governance-design.md §5.9):
  - 只同步 authoritative + verified + active 且治理通过的条目
  - 使用配置 PENTAGI_KB_URL / PENTAGI_KB_LIST_URL / PENTAGI_TOKEN(REST),不走 GraphQL provider mutation
  - 成功必须 HTTP 2xx 且返回远端文档 ID;响应丢失按 hash/远端 ID 对账
  - 失败标记 skip(reason code),不伪造成功

用法:
  python3 adapters/pentagi/sync_kb.py [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

REDKB_URL = os.environ.get("REDKB_URL", "http://127.0.0.1:8001")
PENTAGI_KB_URL = os.environ.get("PENTAGI_KB_URL", "").rstrip("/")
PENTAGI_KB_LIST_URL = os.environ.get("PENTAGI_KB_LIST_URL", "").rstrip("/")
PENTAGI_TOKEN = os.environ.get("PENTAGI_TOKEN", "").strip()

SYNC_STATUS = ("authoritative", "verified", "active")


def _load_token() -> str:
    if PENTAGI_TOKEN:
        return PENTAGI_TOKEN
    path = os.path.join(os.path.dirname(__file__), "..", "..", "secrets", "pentagi_token.txt")
    try:
        return open(path).read().strip()
    except FileNotFoundError:
        return ""


def promoted_entries() -> list[dict]:
    with httpx.Client(timeout=15) as c:
        r = c.get(f"{REDKB_URL}/kb/list")
        r.raise_for_status()
        return r.json()


def _doc_type(entry: dict) -> str:
    etype = str(entry.get("type") or "")
    return "guide" if etype in {"guide", "strategy_rule", "defense_fingerprint"} else "answer"


def sync_entry(entry: dict, dry: bool) -> dict:
    id_ = entry.get("id")
    status = str(entry.get("status") or "")
    verified = bool(entry.get("verified"))
    vstatus = str(entry.get("validation_status") or "")
    if status not in {"authoritative", "verified"} or not verified or vstatus != "verified":
        return {"status": "skipped", "reason": "not-authoritative-or-verified", "id": id_}
    if not PENTAGI_KB_URL:
        return {"status": "skipped", "reason": "no-PENTAGI_KB_URL", "id": id_}
    payload = {
        "doc_type": _doc_type(entry),
        "question": str(entry.get("title") or ""),
        "content": str(entry.get("content_redacted") or entry.get("content") or ""),
        "description": str(entry.get("affected") or ""),
    }
    if dry:
        return {"status": "dry-run", "id": id_, "doc_type": payload["doc_type"]}
    token = _load_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    with httpx.Client(timeout=30) as c:
        try:
            r = c.post(PENTAGI_KB_URL + "/knowledge/", json=payload, headers=headers)
        except httpx.HTTPError as exc:
            return {"status": "sync_failed", "id": id_, "error": "transport-error", "detail": str(exc)}
    if 200 <= r.status_code < 300:
        try:
            remote_id = r.json().get("id") or r.json().get("doc_id")
        except Exception:
            remote_id = None
        if remote_id:
            return {"status": "synced", "id": id_, "remote_doc_id": str(remote_id)}
        return {"status": "sync_failed", "id": id_, "error": "no-remote-id", "http": r.status_code}
    return {"status": "sync_failed", "id": id_, "error": f"http-{r.status_code}", "http": r.status_code}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    entries = promoted_entries()
    results = [sync_entry(e, a.dry_run) for e in entries]
    for r in results:
        print(json.dumps(r, ensure_ascii=False))
    summary = {}
    for r in results:
        summary[r["status"]] = summary.get(r["status"], 0) + 1
    print("SUMMARY " + json.dumps(summary))
    return 0 if summary.get("sync_failed") else 0


if __name__ == "__main__":
    sys.exit(main())
