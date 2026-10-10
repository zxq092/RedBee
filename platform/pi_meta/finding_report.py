"""单漏洞报告 + 复测（借 ARTEX reporter/retester 触发模式）。

reporter：任务 done 后 fire-and-forget，每条 finding 一个独立 LLM 通道写
单漏洞详细报告（概述/根因/PoC/影响/修复建议）→ findings.report_md。
LLM 挂/超时 → 机械模板降级，保证每条 finding 都有报告。

evidence_version：board.post 补全 poc/evidence 时 +1；报告记录写入时的版本
（report_evidence_version），版本落后 → 下次 done 钩子重写，防"证据变了报告还是旧的"。

retester：POST /api/finding/{id}/retest 派一个聚焦复测任务（单模块、短预算），
done 钩子 settle_retests 按 dedup_key 匹配回写三态判定：
  reproduced      复测打出同 dedup_key finding → 原 finding 升 confirmed
  not_reproduced  复测任务正常完成但无同 key finding（不自动判 false_positive，
                  agent 可能没打出来，留人工判）
  inconclusive    复测任务被取消/出错（目标不可达等），无法判定
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional

from . import board as _board
from . import sessions as _sessions
from .model_runtime import RuntimeClient, resolve_runtime

_RETEST_TABLE = """CREATE TABLE IF NOT EXISTS retests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER NOT NULL,
  retest_task_id TEXT NOT NULL,
  created_at TEXT,
  UNIQUE (retest_task_id)
)"""


def _conn():
    conn = _board._conn()
    conn.execute(_RETEST_TABLE)
    conn.commit()
    return conn


def find_finding_any_task(finding_id: int) -> Optional[Dict[str, Any]]:
    """finding id 全表唯一（AUTOINCREMENT），跨任务查单条。"""
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT id, task_id, target, vuln_class, title, location, poc, evidence, "
            "severity, status, report_md, evidence_version, report_evidence_version, "
            "retest_verdict, retest_at FROM findings WHERE id=?", (finding_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    cols = ["id", "task_id", "target", "vuln_class", "title", "location", "poc", "evidence",
            "severity", "status", "report_md", "evidence_version", "report_evidence_version",
            "retest_verdict", "retest_at"]
    return dict(zip(cols, row))


# ---------------------------------------------------------------- reporter

_REPORT_PROMPT = """你是漏洞报告撰写员。根据下面的 finding 写一份单漏洞详细报告。

要求：
- 直接输出 Markdown，不要用代码块包裹整篇，不要输出 JSON
- 固定小节：## 概述 / ## 根因分析 / ## PoC / ## 影响评估 / ## 修复建议
- PoC 小节原样复述给定 PoC（不要改动载荷）；PoC 为空则写明"未留存 PoC"
- 根因分析与修复建议基于漏洞类型和位置推断，不确定就明说不确定
- 不要编造不存在的证据或响应

TARGET: {target}
FINDING:
- title: {title}
- severity: {severity}
- vuln_class: {vuln_class}
- location: {location}
- poc:
{poc}
- evidence:
{evidence}
"""


def _mechanical_report(f: Dict[str, Any], target: str = "") -> str:
    """LLM 失败降级：机械模板，PoC/证据原样保留。"""
    poc = (f.get("poc") or "").strip() or "(未留存)"
    ev = (f.get("evidence") or "").strip() or "(未留存)"
    return (
        f"## 概述\n\n**{f.get('title') or '(无标题)'}** — {f.get('severity') or 'unknown'}"
        f"（{f.get('vuln_class') or '未分类'}）\n\n"
        f"**目标**: `{target or f.get('target') or '?'}`\n"
        f"**位置**: `{f.get('location') or '(未记录)'}`\n\n"
        f"## PoC\n\n```\n{poc}\n```\n\n"
        f"## 证据\n\n```\n{ev}\n```\n\n"
        f"> 本报告为机械模板生成（LLM 报告通道失败或超时），PoC 与证据为 agent 原始记录。"
    )


def _strip_code_fence(md: str) -> str:
    md = (md or "").strip()
    if md.startswith("```"):
        md = re.sub(r"^```[a-zA-Z]*\s*\n?", "", md)
        md = re.sub(r"\n?```\s*$", "", md)
    return md.strip()


async def _llm_report(runtime, model: str, f: Dict[str, Any], target: str) -> Optional[str]:
    prompt = _REPORT_PROMPT.format(
        target=target or f.get("target") or "?",
        title=f.get("title") or "(无标题)",
        severity=f.get("severity") or "unknown",
        vuln_class=f.get("vuln_class") or "(未分类)",
        location=f.get("location") or "(未记录)",
        poc=(f.get("poc") or "(未留存)")[:3000],
        evidence=(f.get("evidence") or "(未留存)")[:3000],
    )
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}],
               "max_tokens": 2500, "temperature": 0.2}
    result = await asyncio.wait_for(RuntimeClient.chat(runtime, payload), timeout=120.0)
    if not result.ok:
        return None
    md = _strip_code_fence(result.content)
    if len(md) < 80:
        return None
    return md


async def write_finding_reports(task_id: str, max_findings: int = 20) -> int:
    """任务 done 后 fire-and-forget：为本任务 findings 写单漏洞报告。

    只重写"无报告"或"证据版本落后"的条目（幂等，重跑不重复烧 LLM）。返回写入条数。
    """
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT id, target, vuln_class, title, location, poc, evidence, severity, "
            "report_md, evidence_version, report_evidence_version "
            "FROM findings WHERE task_id=? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, id LIMIT ?", (task_id, max_findings)).fetchall()
    finally:
        conn.close()
    stale = [dict(zip(["id", "target", "vuln_class", "title", "location", "poc", "evidence",
                       "severity", "report_md", "evidence_version", "report_evidence_version"], r))
             for r in rows
             if not r["report_md"] or (r["report_evidence_version"] or 0) < (r["evidence_version"] or 1)]
    if not stale:
        return 0
    runtime = None
    model = ""
    try:
        res = await resolve_runtime()
        if res.ok and res.runtime is not None:
            runtime = res.runtime
            model = runtime.runtime.model
    except Exception:
        runtime = None
    written = 0
    conn = _conn()
    try:
        for f in stale:
            md: Optional[str] = None
            if runtime is not None:
                try:
                    md = await _llm_report(runtime, model, f, f.get("target") or "")
                except Exception:
                    md = None
            if md is None:
                md = _mechanical_report(f, f.get("target") or "")
            conn.execute(
                "UPDATE findings SET report_md=?, report_evidence_version=evidence_version "
                "WHERE task_id=? AND id=?", (md, task_id, f["id"]))
            conn.commit()
            written += 1
    finally:
        conn.close()
    print(f"[finding-report] task={task_id} 写入 {written}/{len(stale)} 份单漏洞报告"
          f"（model={model or 'mechanical'}）", flush=True)
    return written


# ---------------------------------------------------------------- retester

def retest_prompt(f: Dict[str, Any]) -> str:
    poc = (f.get("poc") or "").strip() or "(原 finding 未留存 PoC，按漏洞类型自行构造最小复现)"
    return (
        "这是一个**复测任务**（不是泛化渗透）：验证一条已知漏洞是否仍然可复现。\n\n"
        f"漏洞: {f.get('title') or '(无标题)'}（{f.get('vuln_class') or '未分类'}, "
        f"{f.get('severity') or 'unknown'}）\n"
        f"位置: {f.get('location') or '(见 PoC)'}\n"
        f"原 PoC:\n```\n{poc[:2500]}\n```\n\n"
        "任务要求：\n"
        "1. 只针对这条漏洞做复现，不要探索其他漏洞\n"
        "2. 执行原 PoC（或等价最小攻击）一次，看是否仍能触发\n"
        "3. **仍可复现** → submit_finding（title/location 与原漏洞保持一致，便于自动匹配），"
        "evidence 带本次复现的关键响应\n"
        "4. **不可复现**（404/参数失效/行为正常）或**目标不可达** → 不要 submit_finding，"
        "在最终总结里写明原因；目标不可达时总结必须包含字符串 TARGET_UNREACHABLE\n"
        "5. 别过度验证：一次干净判定就收口"
    )


def record_retest(finding_id: int, retest_task_id: str) -> None:
    conn = _conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO retests (finding_id, retest_task_id, created_at) "
            "VALUES (?,?,?)", (finding_id, retest_task_id, _sessions.utcnow()))
        conn.commit()
    finally:
        conn.close()


def pending_retests_for_task(task_id: str) -> List[int]:
    conn = _conn()
    try:
        rows = conn.execute("SELECT finding_id FROM retests WHERE retest_task_id=?",
                            (task_id,)).fetchall()
    finally:
        conn.close()
    return [r["finding_id"] if isinstance(r, dict) else r[0] for r in rows]


def settle_retests(task_id: str, final_status: str) -> int:
    """复测任务结束后结算三态判定并回写原 finding。返回结算条数。"""
    finding_ids = pending_retests_for_task(task_id)
    if not finding_ids:
        return 0
    conn = _conn()
    try:
        new_keys = {r[0] for r in conn.execute(
            "SELECT dedup_key FROM findings WHERE task_id=?", (task_id,)).fetchall()}
    finally:
        conn.close()
    n = 0
    conn = _conn()
    try:
        for fid in finding_ids:
            row = conn.execute(
                "SELECT id, task_id, dedup_key, status FROM findings WHERE id=?", (fid,)).fetchone()
            if row is None:
                continue
            origin_task, origin_key = row["task_id"], row["dedup_key"]
            hit = origin_key in new_keys
            if hit and final_status == "done":
                verdict = "reproduced"
            elif final_status == "done":
                verdict = "not_reproduced"
            else:
                verdict = "inconclusive"
            conn.execute(
                "UPDATE findings SET retest_verdict=?, retest_at=? WHERE id=?",
                (verdict, _sessions.utcnow(), fid))
            conn.commit()  # 先提交再调 board.mark：后者另开连接写库，避免 SQLite 锁互挡
            if verdict == "reproduced" and row["status"] != "confirmed":
                _board.mark(origin_task, fid, "confirmed", confirmed_by=f"retest:{task_id}")
            print(f"[retest] finding={fid} verdict={verdict} "
                  f"(retest_task={task_id}, origin_task={origin_task})", flush=True)
            n += 1
    finally:
        conn.close()
    return n


__all__ = [
    "find_finding_any_task",
    "write_finding_reports",
    "retest_prompt",
    "record_retest",
    "pending_retests_for_task",
    "settle_retests",
]
