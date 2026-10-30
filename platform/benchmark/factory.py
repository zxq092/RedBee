"""数据工厂 CLI —— 批量产"已解出 flag"的攻击轨迹（SFT/DPO/RED-KB RAG 原料）。

流程：picoCTF 题库(带官方 hints oracle) → 经网关跑 RedBee(dump_trajectory=1)
→ 真值比对 → solved 的完整 messages 轨迹归档 data/factory/solved/，manifest 记账。
断点续跑：manifest 里已 solved 的跳过；默认已尝试过的也跳（--retry-failed 重打）。

用法：
  python3 -m benchmark.factory --bench picoctf --timeout-min 12 --hints 1
  python3 -m benchmark.factory --bench picoctf --ids pico21-forensics-matryoshka-doll
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .adapters import get_adapter
from .base import _client, dispatch, receive_done, extract_flag, board_findings

FACTORY_DIR = Path(__file__).resolve().parents[2] / "data" / "factory"
MANIFEST = FACTORY_DIR / "manifest.jsonl"


def _load_manifest() -> dict:
    """{"<cid>": {"status": "solved|failed", ...}}"""
    out: dict = {}
    if MANIFEST.exists():
        for line in MANIFEST.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
                out[r["id"]] = r
            except Exception:
                continue
    return out


def _append_manifest(rec: dict) -> None:
    FACTORY_DIR.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _find_traj(task_id: str) -> list[Path]:
    d = Path(__file__).resolve().parents[2] / "data" / "trajectories"
    return sorted(d.glob(f"{task_id}__*.json")) if d.exists() else []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bench", default="picoctf")
    ap.add_argument("--ids", help="comma-separated ids（默认 spec 全量）")
    ap.add_argument("--gateway", default="http://127.0.0.1:8100")
    ap.add_argument("--timeout-min", type=int, default=12)
    ap.add_argument("--session-prefix", default="factory")
    ap.add_argument("--model", default="")
    ap.add_argument("--hints", type=int, default=1,
                    help="oracle 提示注入条数（0=纯净评测模式）")
    ap.add_argument("--retry-failed", action="store_true", help="重打 manifest 里 failed 的题")
    ap.add_argument("--token", default="")
    opts = ap.parse_args()

    # oracle 提示分级（picoctf adapter 的模块级开关）
    from .adapters import picoctf as _pico_mod
    _pico_mod.HINTS_LEVEL = max(0, opts.hints)

    adapter = get_adapter(opts.bench)
    print(f"[factory] backend={adapter.name} hints={opts.hints} timeout={opts.timeout_min}min "
          f"model={opts.model or adapter.default_model or '(全局)'}", flush=True)
    targets = adapter.list_targets()
    ids = {x.strip() for x in (opts.ids or "").split(",") if x.strip()}
    if ids:
        targets = [t for t in targets if t["cid"] in ids]
    done_map = _load_manifest()
    if not opts.retry_failed:
        targets = [t for t in targets if t["cid"] not in done_map]
    if not targets:
        print("[factory] 无待跑目标（全部已在 manifest）。")
        return 0

    client = _client(opts.gateway, opts.token)
    solved_n = failed_n = 0
    for tgt in targets:
        cid = tgt["cid"]
        t0 = time.time()
        try:
            task_id = dispatch(adapter, tgt, client, opts.session_prefix,
                               opts.timeout_min * 60, opts.model or "",
                               dump_trajectory=True)
        except Exception as e:
            print(f"[factory] {cid} 派发失败: {e}", flush=True)
            _append_manifest({"id": cid, "status": "dispatch_error", "error": str(e)[:160],
                              "ts": time.strftime("%FT%T")})
            continue
        status, elapsed = receive_done(task_id, client, opts.timeout_min * 60)
        flags = extract_flag(task_id, client)
        known = (tgt.get("flag") or "").strip()
        hit = any(known == f.strip() or known in f for f in flags) if known else bool(flags)
        rec = {"id": cid, "task_id": task_id, "status": status, "solved": hit,
               "flags": flags[:3], "findings": board_findings(task_id, client),
               "elapsed_s": round(elapsed, 1), "ts": time.strftime("%FT%T")}
        if hit:
            solved_n += 1
            # 轨迹归档（合并 spec 元数据）。引擎常在 receive_done 放弃后才收口（晚到 done），
            # 轨迹文件落在 child finalize 时刻——首轮找不到时延迟 90s 重试一次补归档。
            trajs = _find_traj(task_id)
            if not trajs:
                time.sleep(90)
                trajs = _find_traj(task_id)
            solved_dir = FACTORY_DIR / "solved"
            solved_dir.mkdir(parents=True, exist_ok=True)
            for tr in trajs:
                try:
                    data = json.loads(tr.read_text(encoding="utf-8"))
                except Exception:
                    continue
                data["factory"] = {"cid": cid, "flag": known, "category": tgt.get("category", ""),
                                   "desc": tgt.get("desc", ""), "bench": adapter.name}
                out = solved_dir / f"{cid}.json"
                out.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
                rec["trajectory"] = str(out)
                rec["traj_msgs"] = len(data.get("messages", []))
            _append_manifest(rec)
            print(f"[factory] {cid} ✅ SOLVED {rec['elapsed_s']}s "
                  f"traj={rec.get('traj_msgs', 0)}msgs -> {rec.get('trajectory', '无')}", flush=True)
        else:
            failed_n += 1
            _append_manifest(rec)
            print(f"[factory] {cid} ❌ {status} findings={rec['findings']}", flush=True)
    total = solved_n + failed_n
    print(f"\n== FACTORY: {solved_n}/{total} solved（本次）| manifest 累计 "
          f"{sum(1 for r in _load_manifest().values() if r.get('solved'))} solved", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
