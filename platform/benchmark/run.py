"""Benchmark CLI — drive RedBee (as the agent) through the gateway against a fixed challenge
suite from any registered benchmark backend, collect flags + metrics, and print a score.

Pure-additive harness layer; never touches the engine. See benchmark/base.py for the driver.

Examples:
  python3 -m benchmark.run --bench xben --ids xben-069-24,xben-035-24 --timeout-min 15
  python3 -m benchmark.run --bench cybench --ids cyb-1
  python3 -m benchmark.run --bench exploitgym --ids x   # refused (capability-gated)
"""
from __future__ import annotations

import argparse
import sys

from .adapters import get_adapter
from .base import run_suite, _client, score


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bench", required=True,
                    help="xben | cybench | exploitgym | exploitbench | cybergym")
    ap.add_argument("--ids", help="comma-separated challenge ids to run (default: all listed)")
    ap.add_argument("--gateway", default="http://127.0.0.1:8100")
    ap.add_argument("--timeout-min", type=int, default=15)
    ap.add_argument("--session-prefix", default="bench")
    ap.add_argument("--token", default="")
    ap.add_argument("--model", default="",
                    help="本批任务专用模型（如 DeepSeek-V4-Flash/qwen3.8-27b；缺省用 backend default_model）")
    ap.add_argument("--allow-binary", action="store_true",
                    help="显式放行二进制 benchmark（否则 capability 未就绪会拒绝）")
    opts = ap.parse_args()

    adapter = get_adapter(opts.bench)
    print(f"[bench] backend={adapter.name} ({adapter.category}) — {adapter.describe()}", flush=True)
    if adapter.category == "binary" and not opts.allow_binary:
        raise SystemExit(
            f"[{adapter.name}] 二进制能力未就绪，拒绝启动。"
            "RedBee 现仅 Web/CTF 黑盒渗透、无二进制利用工具链；"
            "请先扩展逆向/pwn 工具族，再加 --allow-binary 显式放行。")

    client = _client(opts.gateway, opts.token)
    results = run_suite(adapter, client, opts)
    print(f"\n{'id':<18}{'status':<13}{'solved':<7}{'findings':<9}{'elapsed_s':<10}flag", flush=True)
    for r in results:
        print(f"{r['id']:<18}{r.get('status',''):<13}{str(r.get('solved')):<7}"
              f"{str(r.get('findings',0)):<9}{str(r.get('elapsed_s','')):<10}"
              f"{(r.get('flags') or [''])[0][:40]}", flush=True)
    sc = score(results)
    print(f"\n== SCORE: {sc['solved']}/{sc['total']} solved | avg {sc['avg_s']}s/task", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
