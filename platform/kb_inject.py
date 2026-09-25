"""知识库注入助手: 派活时检索 RED-KB 相关 top-K, 内容化烘进 agent 指令/prompt.

黑盒安全: 不依赖 agent 中途调工具, 把"相关的知识内容本身"放进任务/prompt。
用法:
  python3 kb_inject.py --query "prompt injection LLMVault" --scope llmvault --out /tmp/kb.png
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

import httpx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import REDKB_URL

# 只注入这些类型(打法/避坑/策略),注入条数上限(上下文控制)
INJECT_TYPES = {"attack_primitive", "poc", "trap", "strategy_rule", "cve_entry"}
TOP_K = 8


async def fetch_relevant(query: str, scope: str | None, tags: list[str] | None,
                         limit: int = TOP_K) -> list[dict]:
    q = {"query": query, "include_candidates": False,  # 只取权威, 过滤噪音
         "types": sorted(INJECT_TYPES), "tags": tags, "limit": limit}
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(f"{REDKB_URL}/kb/query", json=q)
        r.raise_for_status()
        return r.json().get("results", [])


def render_kb(entries: list[dict]) -> str:
    lines = ["## 共享知识库 RED-KB —— 已验证可用知识(直接采用, 无需联网)", ""]
    if not entries:
        lines.append("(本次无相关知识,按常规流程与联网补充)")
        return "\n".join(lines)
    for e in entries:
        sev = "权威" if e.get("status") == "authoritative" else "参考"
        lines.append(f"- **[{e.get('type')}/{sev}] {e.get('title')}**")
        lines.append(f"  内容: {str(e.get('content','')).replace(chr(10),' ')[:400]}")
        if e.get("verified"):
            lines.append(f"  (已验证, 来源 {e.get('proof_method','human')})")
    return "\n".join(lines)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", required=True)
    ap.add_argument("--scope", default=None)
    ap.add_argument("--tags", default=None, help="逗号分隔, e.g. llm,webapp")
    ap.add_argument("--out", required=True)
    ap.add_argument("--task", default="对目标做渗透测试。")
    a = ap.parse_args()
    tags = a.tags.split(",") if a.tags else None
    entries = await fetch_relevant(a.query, a.scope, tags)
    body = f"# 任务\n{a.task}\n\n" + render_kb(entries)
    body += "\n\n## 规则\n- 优先采用上述已验证知识; 若与目标不符再联网。\n- 每个发现须验证(二次确认)后再上报, 不单次上报。"
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(body)
    print(f"已注入 {len(entries)} 条知识 -> {a.out}")


if __name__ == "__main__":
    asyncio.run(main())
