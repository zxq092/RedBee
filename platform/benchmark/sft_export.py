"""轨迹库 → SFT 训练格式导出器（数据工厂 v1，2026-10-21）。

输入 data/factory/solved/*.json（factory 归档的完整 messages 轨迹，真值已验证）；
输出 OpenAI chat 格式 JSONL（axolotl/llama-factory 直接可用的 messages 字段）：

  {"messages": [{"role":"system",...},{"role":"user",...},
                {"role":"assistant","content":"","tool_calls":[...]},
                {"role":"tool","tool_call_id":"...","content":"..."}, ...],
   "meta": {"cid","category","turns","tool_calls","flag","bench"}}

清洗策略（保持"模型实际所见"的真实性，最小干预）：
- 保留 compaction 占位符/budget notice（是轨迹真实一部分）
- 默认剔除 msgs < 10 的薄轨迹（--min-msgs 0 关闭）
- 去重：同一 cid 只导一条（manifest 追加修正可能产生多条归档时以最新为准）

DPO 负样本对暂不生成（需要失败分叉的系统性采集，v2 议题）。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SOLVED_DIR = Path(__file__).resolve().parents[2] / "data" / "factory" / "solved"


def load_trajectories(solved_dir: Path = SOLVED_DIR) -> dict[str, dict]:
    """cid -> 最新轨迹（同 cid 多文件时按 mtime 取新）。"""
    out: dict[str, tuple[float, dict]] = {}
    for f in sorted(solved_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        cid = data.get("factory", {}).get("cid") or f.stem
        mtime = f.stat().st_mtime
        if cid not in out or mtime > out[cid][0]:
            out[cid] = (mtime, data)
    return {cid: d for cid, (_, d) in out.items()}


def to_sft_record(data: dict) -> dict:
    fac = data.get("factory", {})
    msgs = data.get("messages", [])
    # 只保留 OpenAI 会话合法角色；tool 消息需带 tool_call_id（导出侧不修补，坏行走丢并计数）
    cleaned, dropped = [], 0
    for m in msgs:
        role = m.get("role")
        if role not in ("system", "user", "assistant", "tool"):
            dropped += 1
            continue
        if role == "tool" and not m.get("tool_call_id"):
            dropped += 1
            continue
        cleaned.append(m)
    return {
        "messages": cleaned,
        "meta": {
            "cid": fac.get("cid", ""), "category": fac.get("category", ""),
            "bench": fac.get("bench", "picoctf"), "flag": fac.get("flag", ""),
            "turns": data.get("turns", 0), "tool_calls": data.get("tool_calls", 0),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--solved-dir", default=str(SOLVED_DIR))
    ap.add_argument("--out", default=str(SOLVED_DIR.parent / "sft_v1.jsonl"))
    ap.add_argument("--min-msgs", type=int, default=10)
    args = ap.parse_args()

    trajs = load_trajectories(Path(args.solved_dir))
    kept = []
    for cid, data in trajs.items():
        rec = to_sft_record(data)
        if len(rec["messages"]) < args.min_msgs:
            continue
        kept.append(rec)
    out = Path(args.out)
    with open(out, "w", encoding="utf-8") as f:
        for rec in kept:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    total_msgs = sum(len(r["messages"]) for r in kept)
    cats: dict[str, int] = {}
    for r in kept:
        cats[r["meta"]["category"] or "?"] = cats.get(r["meta"]["category"] or "?", 0) + 1
    print(f"sft 导出: {len(kept)}/{len(trajs)} 条（min_msgs={args.min_msgs}）-> {out}")
    print(f"  总消息数 {total_msgs} | 类别分布 {cats}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
