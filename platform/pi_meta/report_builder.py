"""正式渗透测试报告生成模块 (Formal pentest report builder).

给自研 RedBee agent 平台生成面向用户的、人类可读的 Markdown 渗透测试报告。
与 pi_meta/report.py(多 agent 聚合/去重)不同, 本模块面向"单任务终态报告文档":
从 pimeta.db 按 task_id 读取 findings + coverage, 排版成专业报告。

只读, 不改任何核心; 新端点 pi_meta/app.py::task_report 调用 build_markdown_report。
"""
from __future__ import annotations

import os
import re
import sqlite3
from typing import Any, Dict, List, Optional

from config import PIMETA_DB_PATH

DB_PATH = PIMETA_DB_PATH

# 严重度排序 + 展示名
SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEV_LABEL = {"critical": "严重 (Critical)", "high": "高 (High)", "medium": "中 (Medium)",
             "low": "低 (Low)", "info": "信息 (Info)"}
STATUS_LABEL = {"found": "已发现 (Found, 待独立复现)",
                "confirmed": "已确认 (Confirmed — 已被另一 agent 独立复现)",
                "false_positive": "误报 (False Positive)",
                "suspect": "待复核 (Suspect)"}
# outcome 展示名
OUTCOME_LABEL = {"reported": "已上报 (有对应发现)",
                 "confirmed": "已确认",
                 "no_issue_found": "未发现问题",
                 "ruled_out": "已排除 (无此漏洞)",
                 "not_applicable": "不适用",
                 "needs_follow_up": "需跟进"}
# 默认评估模块集(与 planner MODULES 对齐; root 决策未记录时用它做 gap 对账)
DEFAULT_MODULES = ["sqli", "xss", "auth", "upload"]
MODULE_NAME = {"sqli": "SQL 注入 (SQL Injection)", "xss": "跨站脚本 (XSS)",
               "auth": "认证/会话 (Authentication)", "upload": "文件上传 (File Upload)",
               "ssrf": "服务端请求伪造 (SSRF)", "rce": "远程代码执行 (RCE)",
               "lfi": "路径遍历/文件包含 (LFI)", "csrf": "跨站请求伪造 (CSRF)",
               "idor": "越权/对象级授权 (IDOR/BOLA)"}


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}
    for col in ("confirmed_by", "confirmed_at"):
        if col not in cols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT")
    conn.commit()
    return conn


def query_findings(task_id: str) -> List[Dict[str, Any]]:
    """按 task_id 从 pimeta.db 读 findings(自有查询, 与 orchestrator._collect_findings 对齐)。
    返回全部状态(含 found/confirmed/false_positive), 供报表区分; 漏洞明细默认只列非误报。"""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id,task_id,target,dedup_key,vuln_class,title,location,poc,evidence,"
            "severity,status,found_by,confirmed_by,created_at,confirmed_at "
            "FROM findings WHERE task_id=? ORDER BY id", (task_id,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def query_coverage(task_id: str) -> List[Dict[str, Any]]:
    """按 task_id 从 pimeta.db 读 coverage 台账(自有查询)。"""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT surface,risk_area,outcome,evidence,created_at "
            "FROM coverage WHERE task_id=? ORDER BY id", (task_id,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def query_task_metadata(task_id: str) -> Dict[str, Any]:
    from . import sessions
    return sessions.get_task_metadata(task_id)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _entry_is_about(entry: Dict[str, Any], module: str) -> bool:
    phrasings = {
        "sqli": ("sql injection", "sqli"),
        "xss": ("xss", "cross site scripting", "cross-site scripting"),
        "auth": ("authentication", "auth", "login", "credential", "password", "session"),
        "upload": ("file upload", "upload", "insecure file"),
        "ssrf": ("ssrf", "server side request forgery"),
        "rce": ("rce", "remote code execution", "command injection"),
        "lfi": ("path traversal", "lfi", "file inclusion"),
        "csrf": ("csrf", "cross site request forgery"),
        "idor": ("idor", "object level authorization", "bola"),
    }.get(module, (module,))
    hay = _norm(f"{entry.get('risk_area','')} {entry.get('surface','')}").split()
    return any(all(t in hay for t in _norm(p).split()) for p in phrasings)


def _reconcile(rows: List[Dict[str, Any]], modules: List[str]) -> Dict[str, Any]:
    """模块对账: 派发的模块里哪些没有 coverage 记录 = 未测 gap。"""
    covered = {m for m in modules if any(_entry_is_about(r, m) for r in rows)}
    gaps = [m for m in modules if m not in covered]
    return {"covered": sorted(covered), "gaps": sorted(gaps)}


def _infer_target(findings: List[Dict[str, Any]]) -> str:
    for f in findings:
        if f.get("target"):
            return f["target"]
    for f in findings:
        loc = f.get("location") or ""
        m = re.search(r"(https?://[^\s/?]+)", loc)
        if m:
            return m.group(1)
    return "N/A (未记录)"


def _severity_count(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    c: Dict[str, int] = {}
    for f in findings:
        c[f.get("severity", "info").lower()] = c.get(f.get("severity", "info").lower(), 0) + 1
    return c


def build_markdown_report(task_id: str, findings: List[Dict[str, Any]],
                          coverage: Optional[Dict[str, Any]] = None) -> str:
    """构建正式 Markdown 渗透测试报告。

    参数:
      task_id:  任务 ID(仅用于标题/上下文)
      findings: 该 task 的 findings 列表(字段: title/location/severity/vuln_class/poc/
                evidence/status/found_by/confirmed_by 等, 来自 pimeta.db)
      coverage: 覆盖对账 dict, 可含:
                  rows:             coverage 台账行列表(surface/risk_area/outcome/evidence)
                  assigned_modules: 实际派发的模块列表(可选; 缺省用 DEFAULT_MODULES)
                  recon:            预计算的对账结果(可选, 缺省按 rows 自行对账)
                  target:           目标字符串(可选; 缺省从 findings 推断)
    返回: 完整 Markdown 报告文本。
    """
    coverage = coverage or {}
    rows = list(coverage.get("rows") or [])
    assigned = list(coverage.get("assigned_modules")
                    or [m for m in DEFAULT_MODULES if m in MODULE_NAME])
    recon = coverage.get("recon") or _reconcile(rows, assigned)
    target = coverage.get("target") or _infer_target(findings)

    real = [f for f in findings if str(f.get("status", "found")).lower() not in {"false_positive", "suspect"}]
    real_sorted = sorted(real, key=lambda f: SEV_ORDER.get(str(f.get("severity", "info")).lower(), 0),
                         reverse=True)
    sev_counts = _severity_count(real)
    total = len(real)

    L: List[str] = []
    # ---------- 标题/元信息 ----------
    L.append(f"# 渗透测试报告")
    L.append("")
    L.append(f"- **任务 ID**: `{task_id}`")
    L.append(f"- **目标**: `{target}`")
    L.append(f"- **生成时间**: {_now()}")
    L.append(f"- **评估引擎**: RedBee (自研渗透 agent)")
    L.append("")
    L.append("---")
    L.append("")

    # ---------- 执行摘要 ----------
    L.append("## 1. 执行摘要 (Executive Summary)")
    L.append("")
    L.append(f"本次针对 `{target}` 的渗透测试共发现 **{total}** 个有效漏洞。"
             f"按严重度分级: 严重 **{sev_counts.get('critical', 0)}**、高 **{sev_counts.get('high', 0)}**"
             f"、中 **{sev_counts.get('medium', 0)}**、低 **{sev_counts.get('low', 0)}**、"
             f"信息 **{sev_counts.get('info', 0)}**。")
    L.append("")
    if recon.get("gaps"):
        L.append(f"另有 **{len(recon['gaps'])}** 个评估模块未完成充分覆盖(见第 4 节对账), "
                 f"报告范围外的攻击面未作『已确认干净』结论。")
        L.append("")
    if total:
        L.append("**最高风险问题**:")
        L.append("")
        for f in real_sorted[:5]:
            sev = str(f.get("severity", "info")).lower()
            L.append(f"- [{SEV_LABEL.get(sev, sev)}] `{f.get('title')}` — 位于 `{f.get('location') or '(未记录)'}`")
        L.append("")
    else:
        L.append("未发现可确认的漏洞。若存在未覆盖模块, 请结合第 4 节对账判断测试完备性。")
        L.append("")
    L.append("---")
    L.append("")

    # ---------- 发现明细 ----------
    L.append("## 2. 发现明细 (Findings)")
    L.append("")
    if not real_sorted:
        L.append("无有效发现。")
        L.append("")
    for i, f in enumerate(real_sorted, 1):
        sev = str(f.get("severity", "info")).lower()
        status = str(f.get("status", "found")).lower()
        loc = f.get("location") or "(未记录)"
        vclass = f.get("vuln_class") or "未分类"
        L.append(f"### 2.{i} {f.get('title')}")
        L.append("")
        L.append(f"| 属性 | 值 |")
        L.append(f"|------|----|")
        L.append(f"| 严重度 | **{SEV_LABEL.get(sev, sev)}** |")
        L.append(f"| 位置 | `{loc}` |")
        L.append(f"| 漏洞类型 | {vclass} |")
        L.append(f"| 状态 | {STATUS_LABEL.get(status, status)} |")
        L.append(f"| 发现者 | {f.get('found_by') or 'RedBee'} |")
        if status == "confirmed":
            L.append(f"| 确认者 | {f.get('confirmed_by') or '(未记录)'} |")
        L.append("")
        if f.get("evidence"):
            L.append(f"**证据节选**:")
            L.append("")
            L.append("```")
            L.append(_truncate(f["evidence"], 1200))
            L.append("```")
            L.append("")
        if f.get("poc"):
            L.append(f"**PoC (Proof of Concept)**:")
            L.append("")
            L.append("```")
            L.append(_truncate(f["poc"], 800))
            L.append("```")
            L.append("")
        L.append("---")
        L.append("")

    # ---------- 覆盖对账 ----------
    L.append("## 3. 覆盖对账 (Coverage Reconciliation)")
    L.append("")
    L.append("下面的对账展示评估模块下, 哪些已测、哪些派发了却没覆盖(视为未测 gap, 而非干净)。")
    L.append("")
    L.append("| 模块 | 状态 |")
    L.append("|------|------|")
    for m in assigned:
        label = MODULE_NAME.get(m, m)
        if m in recon.get("gaps", []):
            L.append(f"| {label} | ⚠️ **未覆盖 (gap)** — 派发但无记录, 按未测处理 |")
        else:
            L.append(f"| {label} | ✅ 已覆盖 |")
    if not assigned:
        L.append("(未记录派发模块, 无对账依据)")
    L.append("")
    if rows:
        L.append("**测试台账 (Recorded Coverage)**:")
        L.append("")
        L.append("| 攻击面 | 风险区 | 结果 | 证据节选 |")
        L.append("|--------|--------|------|----------|")
        for r in rows[:40]:
            outcome = str(r.get("outcome", "?")).lower()
            L.append(f"| `{r.get('surface') or '(n/a)'}` | {r.get('risk_area') or '(n/a)'} | "
                     f"{OUTCOME_LABEL.get(outcome, outcome)} | {_truncate(r.get('evidence'), 50)} |")
        L.append("")
        if len(rows) > 40:
            L.append(f"*…另有 {len(rows) - 40} 条记录未列出。*")
            L.append("")
    L.append("---")
    L.append("")

    # ---------- 建议 ----------
    L.append("## 4. 修复建议 (Recommendations)")
    L.append("")
    if real_sorted:
        L.append("按优先级(从最高风险开始)建议修复以下问题:")
        L.append("")
        for f in real_sorted[:10]:
            sev = str(f.get("severity", "info")).lower()
            L.append(f"- [{SEV_LABEL.get(sev, sev)}] `{f.get('title')}` — `{f.get('location') or '(未记录)'}`")
        L.append("")
    else:
        L.append("无待修复漏洞。")
        L.append("")
    if recon.get("gaps"):
        L.append(f"另请补齐未覆盖模块 `{', '.join(recon['gaps'])}` 的测试, 以排除残留风险。")
        L.append("")

    # ---------- 结论 ----------
    covered_all = not recon.get("gaps")
    L.append("## 5. 结论 (Conclusion)")
    L.append("")
    if total and covered_all:
        L.append(f"目标 `{target}` 存在 **{total}** 个己确认/已发现漏洞, 且所有计划模块均已覆盖。"
                 f"建议优先修复高严重度问题后重新验证。")
    elif total and not covered_all:
        L.append(f"目标 `{target}` 存在 {total} 个漏洞; 但因存在未覆盖模块(gap), "
                 f"本次评估不能视为完整, 建议补齐后再出最终结论。")
    elif not total and covered_all:
        L.append(f"目标 `{target}` 在已覆盖范围内未发现可确认漏洞。")
    else:
        L.append(f"目标 `{target}` 在已覆盖范围内未发现漏洞, 但存在未覆盖模块, 需补充测试确认。")
    L.append("")

    return "\n".join(L)


def _now() -> str:
    try:
        import time
        return time.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def _truncate(s: Any, n: int) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n] + f"\n…[截断, 共 {len(s)} 字符]"
