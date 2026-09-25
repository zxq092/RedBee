#!/usr/bin/env python3
"""LLM 专家知识提炼器: 把渗透报告/轨迹 用 LLM 提炼成专家级 attack_primitive.

核心(符合"像人积累专家知识"):
  不再用正则/模板, 而是把完整渗透报告喂给 LLM, 让它提炼出每条:
    - method     : 攻击手法(具体payload/端点)
    - detection  : 判别逻辑(看到什么响应特征→判断是X漏洞)
    - chain      : 利用链(入口→提权→下一步)
    - preconditions / bypass

输入源(带完整思路的报告):
  - PentAGI: flow 的 task.result(总结报告) + messageLogs 的 thoughts(推理)
  - Strix  : penetration_test_report.md + vulnerabilities/*.md
  - 手写    : 自定义报告文本

用法:
  python3 llm_expert_extractor.py --flow 22            # PentAGI flow
  python3 llm_expert_extractor.py --strix <report.md>  # Strix 报告
  python3 llm_expert_extractor.py --dry-run            # 只预览不写入
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import httpx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import REDKB_URL
from pi_meta.model_runtime import ModelRuntime, ResolvedRuntime, RuntimeClient

PENTAGI_URL = os.environ.get("PENTAGI_URL", "")
PENTAGI_TOKEN = os.environ.get("PENTAGI_TOKEN", "")

SYSTEM_PROMPT = """你是资深渗透测试专家兼知识工程师。你的任务：从一份渗透测试记录/报告中，提炼出**可复用的专家级攻击知识（attack primitive）**，用于武装 AI 渗透 agent 未来打任何同类目标。

请按以下 JSON 结构逐条输出（每条一个漏洞/攻击手法）：
[
  {
    "technique": "sqli|jwt|xxe|lfi|ssrf|nosql|xss|rce|ssti|deserialization|crypto|auth|idor|csrf|...",
    "title": "一句话总结这条攻击",
    "method": "具体攻击手法，含端点/参数/可复现的 payload/curl",
    "detection": "判别逻辑——看到什么响应特征/现象说明该漏洞存在（最重要，像人一样判断）",
    "chain": "利用链——拿到当前成果后下一步怎么做（提权/横向/拿flag）",
    "preconditions": "该攻击成立的前置条件/指纹",
    "bypass": ["可能的绕过/变体"],
    "endpoint": "攻击端点(如 GET /rest/products/search?q=)",
    "evidence": "报告里给出的验证证据/flag/响应片段"
  }
]

要求：
- 内容要**具体、可操作、可复用**，不要空泛
- detection 必须是"判别特征"，而不是"验证成功"这种废话
- method 要保留可复现的 payload/curl 命令，但**用省略号压缩超长部分**（如 UNION 占位列写成 `SELECT 1,2,3,...,N`），不要列出 80 个占位值，控制在每条 300 字符内
- 只输出一个 JSON 数组，不要任何前后缀、不要 markdown 代码块围栏、不要解释文字"""


def _gql(q):
    with httpx.Client(timeout=60, verify=False) as c:
        r = c.post(f"{PENTAGI_URL}/api/v1/graphql",
                   headers={"Authorization": f"Bearer {PENTAGI_TOKEN}",
                            "Content-Type": "application/json"}, json={"query": q})
        return r.json()["data"]


def gather_pentagi(flow_id: int) -> str:
    """收集 flow 的报告 + thoughts 推理, 拼成输入。"""
    d = _gql("{ messageLogs(flowId: %d){ type message } tasks(flowId:%d){ result } }" % (flow_id, flow_id))
    parts = []
    for t in d.get("tasks", []):
        r = str(t.get("result") or "")
        if r:
            parts.append("=== 报告 ===")
            parts.append(r[:8000])
    # thoughts 里挑有价值的(含端点/payload/攻击词的)
    import re
    valuable = []
    for m in d.get("messageLogs", []):
        if m.get("type") not in ("thoughts", "assistant"):
            continue
        msg = str(m.get("message") or "")
        if re.search(r'(POST|GET|PUT|curl|inject|payload|/rest|/api|/ftp|bypass|exfil|solved via|requires|trigger|UNION|JWT|\$gt?|\$ne|%.00|2500)', msg, re.I) \
           and not re.search(r'(Memory search|Compiled the|Generated .*plan|Baseline)', msg, re.I):
            valuable.append(msg)
    if valuable:
        parts.append("=== agent 推理轨迹(思路) ===")
        parts.append("\n".join("· " + v[:300] for v in valuable[-60:]))
    return "\n\n".join(parts)


def gather_strix(path: str) -> str:
    return open(path, encoding="utf-8", errors="ignore").read()[:12000]


async def llm_refine(report: str, runtime: ResolvedRuntime | ModelRuntime) -> dict:
    """调统一运行时提炼成结构化 candidate；不直接写 authoritative。"""
    selected = runtime.runtime if isinstance(runtime, ResolvedRuntime) else runtime
    result = await RuntimeClient.chat(selected, {
        "model": selected.model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"以下是渗透测试记录，请提炼攻击知识：\n\n{report[:26000]}"},
        ],
        "max_tokens": 8000,
        "temperature": 0.2,
    })
    if not result.ok or result.error:
        return {"ok": False, "items": [], "runtime_id": selected.runtime_id,
                "error": result.error}
    data = _extract_json_list(result.content)
    if data is not None:
        return {"ok": True, "items": data, "runtime_id": selected.runtime_id, "error": None}
    return {"ok": False, "items": [], "runtime_id": selected.runtime_id,
            "error": {"code": "PARSE_ERROR", "stage": "parse", "model": selected.model,
                      "redacted_message": "json parse failed"}}


def ingest(prim: dict, dry: bool) -> str:
    entry = {
        "id": f"kb.expert.{prim.get('technique','rmk')}.{os.urandom(3).hex()}",
        "type": "attack_primitive",
        "scope": "all",
        "title": f"[expert] {prim.get('title', prim.get('technique'))[:70]}",
        "content": json.dumps({
            "method": prim.get("method", ""),
            "detection": prim.get("detection", ""),
            "chain": prim.get("chain", ""),
            "preconditions": prim.get("preconditions", ""),
            "bypass_techniques": prim.get("bypass", []) or [],
            "endpoint": prim.get("endpoint", ""),
            "evidence": prim.get("evidence", ""),
            "technique": prim.get("technique", "unknown"),
        }, ensure_ascii=False),
        "tags": list(dict.fromkeys([prim.get("technique", "unknown"), "expert", "llm-refined"])),
        "status": "candidate",
        "verified": False,
        "proof_method": "llm-refinement",
        "source_type": "llm-expert",
        "confidence": 0.8,
    }
    if dry:
        return json.dumps(entry, ensure_ascii=False)[:150]
    with httpx.Client(timeout=20) as c:
        r = c.post(f"{REDKB_URL}/kb/ingest", json=entry)
        return f"{r.status_code}"


import re as _re

def _extract_json_list(content: str):
    """从任意文本中鲁棒提取第一个合法 JSON 数组。"""
    # 去掉任何 ```json 围栏/前后空格
    content = _re.sub(r'```[a-zA-Z]*', '', content)
    # 递增查找 '[' 位置, 尝试解析为数组
    dec = json.JSONDecoder()
    idx = 0
    while True:
        i = content.find('[', idx)
        if i < 0:
            return None
        try:
            obj, _ = dec.raw_decode(content, i)
            if isinstance(obj, list):
                return obj
        except Exception:
            pass
        idx = i + 1


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--flow", type=int, default=None)
    p.add_argument("--strix", default=None)
    p.add_argument("--text", default=None)
    p.add_argument("--file", default=None)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()

    if a.flow:
        report = gather_pentagi(a.flow)
        src = f"flow{a.flow}"
    elif a.strix:
        report = gather_strix(a.strix)
        src = a.strix
    elif a.file:
        report = open(a.file, encoding="utf-8", errors="ignore").read()
        src = a.file
    elif a.text:
        report = a.text
        src = "text"
    else:
        print("需 --flow/--strix/--file/--text"); return

    print(f"[{src}] 报告 {len(report)} 字符, LLM 提炼中(可能需1~3分钟)...", flush=True)
    result = await llm_refine(report)

    if isinstance(result, dict) and result.get("error"):
        print("LLM 提炼失败:", result)
        return

    prims = result if isinstance(result, list) else []
    print(f"LLM 提炼出 {len(prims)} 条专家攻击知识", flush=True)
    for i, pr in enumerate(prims):
        ing = ingest(pr, a.dry_run)
        print(f"  [{i+1}] [{pr.get('technique','?')}] {pr.get('title','')[:55]}")
        print(f"       detect: {str(pr.get('detection',''))[:70]}")
        if a.dry_run:
            print(f"       -> {ing}")
    print(f"\n完成: 提炼并入库 {len(prims)} 条" if not a.dry_run else f"\n(dry-run) 提炼 {len(prims)} 条")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
