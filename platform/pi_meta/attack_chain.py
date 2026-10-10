"""攻击链可视化：任务 done 后 LLM 把工具时间线 + findings 一次性蒸馏成 node/edge 攻击链图，
落 pimeta.db，Web 端渲染时间线/回放。

借鉴 CyberStrikeAI internal/attackchain/builder.go（BuildChainFromConversation：
对话→LLM→nodes/edges JSON→落库→前端回放），适配我们的数据源（task_logs 工具时间线
+ findings 真源），v1 渲染为阶段时间线（recon→exploit→verify），nodes/edges 结构
为 v2 真图预留。
"""
from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Dict, List, Optional

from config import PIMETA_DB_PATH
from . import task_logs
from .model_runtime import RuntimeClient, resolve_runtime

_SCHEMA = """CREATE TABLE IF NOT EXISTS attack_chains (
  task_id TEXT PRIMARY KEY,
  chain_json TEXT NOT NULL,
  model TEXT,
  created_at TEXT
)"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(PIMETA_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute(_SCHEMA)
    conn.commit()
    return conn


def _tool_timeline(task_id: str, limit: int = 220) -> List[str]:
    rows = task_logs.query(task_id)
    out: List[str] = []
    for r in rows:
        if r.get("kind") not in ("tool", "finding", "phase"):
            continue
        ts = str(r.get("ts", ""))[-8:]
        mod = f"[{r['module']}] " if r.get("module") else ""
        out.append(f"{ts} {mod}{r['kind']}: {r.get('detail', '')}")
    return out[-limit:]


def _findings_brief(task_id: str) -> List[Dict[str, Any]]:
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT title, severity, status, vuln_class, location FROM findings "
            "WHERE task_id=? ORDER BY id", (task_id,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def _try_parse_json(content: str) -> Optional[Dict[str, Any]]:
    """解析 LLM 输出的 JSON（支持嵌套：整体→去 fence→首个平衡花括号块）。"""
    content = (content or "").strip()
    if content.startswith("```"):
        content = re.sub(r"^```[a-z]*\n", "", content)
        content = re.sub(r"\n```$", "", content).strip()
    try:
        obj = json.loads(content)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass
    start = content.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(content)):
            ch = content[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(content[start:i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except Exception:
                        pass
                    break
        start = content.find("{", start + 1)
    return None


_PROMPT_TMPL = """You are an attack-chain analyst. Below is the TOOL TIMELINE and FINDINGS of a finished pentest task.
Distill them into an ATTACK CHAIN GRAPH: how the attack unfolded step by step.

RULES:
- nodes: 3-15 nodes, in chronological order. Each: {{"id": <int 1..N>, "phase": "recon"|"exploit"|"verify"|"report", "title": "<=8 words", "detail": "<=25 words, which tool/what was proved>"}}
- edges: {{"from": <node id>, "to": <node id>, "label": "<=4 words, e.g. 'enables', 'escalates'"}} — draw the causal path (recon feeds exploit feeds verify); keep <=15 edges
- findings: map each recorded finding to the node that proved it (node id) in "finding_node"
- risk_score: 0.0-1.0 overall (severity mix)
- summary: ONE sentence narrative of the whole attack
Return STRICT JSON ONLY, no prose:
{{"nodes": [...], "edges": [...], "finding_node": {{"<finding title>": <node id>}}, "risk_score": 0.7, "summary": "..."}}

TARGET: {target}
FINDINGS ({nfind}):
{findings}

TOOL TIMELINE (oldest first, truncated):
{timeline}
"""


async def build_attack_chain(task_id: str, target: str = "") -> Optional[Dict[str, Any]]:
    """任务 done 后调用（fire-and-forget）。LLM 挂/输出不合法 → 静默 None，不影响任务。"""
    timeline = _tool_timeline(task_id)
    findings = _findings_brief(task_id)
    if not timeline:
        return None
    if not target:
        conn = _conn()
        try:
            row = conn.execute(
                "SELECT target FROM findings WHERE task_id=? LIMIT 1", (task_id,)).fetchone()
            target = (row["target"] if row else "") or ""
        finally:
            conn.close()
    findings_text = "\n".join(
        f"- [{f.get('severity')}/{f.get('status')}] {f.get('title')} ({f.get('vuln_class') or ''})"
        for f in findings[:20]) or "(none)"
    prompt = _PROMPT_TMPL.format(
        target=target or "?", nfind=len(findings),
        findings=findings_text[:2000], timeline="\n".join(timeline)[-6000:])
    try:
        res = await resolve_runtime()
        if not res.ok or res.runtime is None:
            return None
        runtime = res.runtime
    except Exception:
        return None
    _model = runtime.runtime.model
    # 全局 LLM 闸门无等待超时（并发任务占满时会一直排队）——fire-and-forget 路径必须自己兜底
    import asyncio
    _chat_timeout = 240.0
    for attempt in range(2):
        payload = {"model": _model, "messages": [{"role": "user", "content": prompt}],
                   "max_tokens": 2000, "temperature": 0.2}
        try:
            result = await asyncio.wait_for(RuntimeClient.chat(runtime, payload), timeout=_chat_timeout)
        except asyncio.TimeoutError:
            print(f"[attack-chain] task={task_id} LLM 超时(>{_chat_timeout:.0f}s，闸门/端点繁忙)，放弃", flush=True)
            return None
        except Exception:
            return None
        if not result.ok or result.error:
            return None
        data = _try_parse_json(result.content)
        if isinstance(data, dict) and isinstance(data.get("nodes"), list) and data["nodes"]:
            data = _normalize(data)
            data["task_id"] = task_id
            _save(task_id, data, _model)
            print(f"[attack-chain] task={task_id} 生成攻击链: {len(data['nodes'])} nodes / "
                  f"{len(data.get('edges', []))} edges", flush=True)
            return data
        prompt += "\n\nYour last output was not valid JSON. Return ONLY the JSON object, no prose."
    return None


def _normalize(data: Dict[str, Any]) -> Dict[str, Any]:
    """裁剪/校验：node 字段白名单、edge 端点必须在 nodes 里、risk_score 归一 [0,1]。"""
    valid_phases = {"recon", "exploit", "verify", "report"}
    nodes: List[Dict[str, Any]] = []
    for i, n in enumerate(data.get("nodes") or []):
        if not isinstance(n, dict):
            continue
        nodes.append({
            "id": int(n.get("id") or len(nodes) + 1),
            "phase": str(n.get("phase") or "exploit") if str(n.get("phase") or "") in valid_phases else "exploit",
            "title": str(n.get("title") or "")[:120],
            "detail": str(n.get("detail") or "")[:300],
        })
    nodes = nodes[:20]
    ids = {n["id"] for n in nodes}
    edges = []
    for e in (data.get("edges") or []):
        if not isinstance(e, dict):
            continue
        f, t = e.get("from"), e.get("to")
        if f in ids and t in ids and f != t:
            edges.append({"from": f, "to": t, "label": str(e.get("label") or "")[:60]})
        if len(edges) >= 20:
            break
    try:
        risk = max(0.0, min(1.0, float(data.get("risk_score", 0.5))))
    except (TypeError, ValueError):
        risk = 0.5
    fn = data.get("finding_node")
    if not isinstance(fn, dict):
        fn = {}
    return {"nodes": nodes, "edges": edges,
            "finding_node": {str(k): int(v) for k, v in fn.items()
                             if isinstance(v, (int, float)) and int(v) in ids},
            "risk_score": round(risk, 2),
            "summary": str(data.get("summary") or "")[:500]}


def _save(task_id: str, data: Dict[str, Any], model: str) -> None:
    from .sessions import utcnow
    conn = _conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO attack_chains (task_id, chain_json, model, created_at) "
            "VALUES (?,?,?,?)",
            (task_id, json.dumps(data, ensure_ascii=False), model, utcnow()))
        conn.commit()
    finally:
        conn.close()


def get_attack_chain(task_id: str) -> Optional[Dict[str, Any]]:
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT chain_json, model, created_at FROM attack_chains WHERE task_id=?",
            (task_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    try:
        data = json.loads(row["chain_json"])
    except Exception:
        return None
    data["model"] = row["model"]
    data["created_at"] = row["created_at"]
    return data
