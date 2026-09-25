import httpx
from typing import Optional, List
from redkb.schemas import KnowledgeEntry, KBQueryResult, CaseRecord


class KBClient:
    """Thin HTTP client used by the gateway and all downstream agents to reach RED-KB."""

    def __init__(self, base_url: str = None):
        self.base_url = base_url or "http://127.0.0.1:8001"

    async def query(self, text: str, types=None, tags=None, limit=5) -> KBQueryResult:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(f"{self.base_url}/kb/query",
                             json={"query": text, "types": types, "tags": tags, "limit": limit})
            r.raise_for_status()
            return KBQueryResult(**r.json())

    async def ingest(self, entry: KnowledgeEntry) -> str:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(f"{self.base_url}/kb/ingest", json=entry.model_dump())
            r.raise_for_status()
            return r.json()["id"]

    async def submit_case(self, record: CaseRecord) -> str:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(f"{self.base_url}/cases/submit", json=record.model_dump())
            r.raise_for_status()
            return r.json()["id"]

    async def list_cases(self) -> list:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(f"{self.base_url}/cases")
            r.raise_for_status()
            return r.json()
