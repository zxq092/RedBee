"""Batch runner: repeatedly drive RedBee over ALL tasks in cybench_tasks.json that don't yet
have a recorded result, appending scores and printing the running X/N. Add new tasks to the
spec as they get deployed/verified; re-running this picks up whatever's new.

Usage:
  setsid nohup python3 -m benchmark.batch --bench cybench --results /tmp/opencode/cyb_results.json \
      --timeout-min 12 > /tmp/opencode/cyb_batch.log 2>&1 &
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .adapters import get_adapter
from .base import run_target, score, _client, POLL_S


def load_results(p: Path) -> dict:
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", default="cybench")
    ap.add_argument("--results", default="/tmp/opencode/cyb_results.json")
    ap.add_argument("--gateway", default="http://127.0.0.1:8100")
    ap.add_argument("--timeout-min", type=int, default=12)
    ap.add_argument("--session-prefix", default="cyb")
    ap.add_argument("--max-rounds", type=int, default=100)
    opts = ap.parse_args()

    adapter = get_adapter(opts.bench)
    client = _client(opts.gateway)
    results = load_results(Path(opts.results))

    for rnd in range(opts.max_rounds):
        targets = adapter.list_targets()
        # 未完成的 = 还没有成功结果，或无结果记录
        pending = [t for t in targets if results.get(t["cid"]) is None]
        if not pending:
            print(f"\n== 全部完成: {score(list(results.values()))}", flush=True)
            return 0
        t = pending[0]
        print(f"\n[round {rnd}] 处理 {t['cid']} @ {t['url']} (剩 {len(pending)})", flush=True)
        try:
            r = run_target(adapter, t, client, opts)
        except Exception as e:
            r = {"id": t["cid"], "status": "error", "solved": False, "findings": 0,
                 "elapsed_s": 0, "error": str(e)}
        results[t["cid"]] = r
        Path(opts.results).write_text(json.dumps(results, ensure_ascii=False, indent=1))
        done = [x for x in results.values() if x.get("status") in ("done",)]
        sc = score(list(results.values()))
        print(f"  -> {t['cid']} {r.get('status')} solved={r.get('solved')} "
              f"findings={r.get('findings')} el={r.get('elapsed_s')} | "
              f"{sc['solved']}/{sc['total']}", flush=True)
        time.sleep(2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
