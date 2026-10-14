"""Cybench backend — 40 CTF tasks from 4 CTF competitions (web-focused, matches RedBee).

Requires a deployment/spec file listing each challenge's id + reachable URL, since Cybench
ships its own task containers. Provide data/benchmark/cybench_tasks.json:
  [{"id":"cyb-<n>","url":"http://<host>:<port>","desc":"..."}]
"""
from __future__ import annotations

import json
from pathlib import Path

from ..base import Adapter

SPEC = Path(__file__).resolve().parents[3] / "data" / "benchmark" / "cybench_tasks.json"


class CybenchAdapter(Adapter):
    name = "cybench"

    def list_targets(self) -> list:
        if not SPEC.exists():
            raise SystemExit(
                f"Cybench 未部署：缺 {SPEC}。请先起 Cybench 任务容器并写 {SPEC}"
                "（[{\"id\":\"cyb-1\",\"url\":\"http://host:port\",\"desc\":\"\"}]）")
        data = json.loads(SPEC.read_text(encoding="utf-8"))
        return [dict(t, desc=t.get("desc", "")) for t in data if t.get("url")]

    def describe(self) -> str:
        return ("40 道 CTF（4 大赛事）的 Web 题，贴合 RedBee。"
                f"需先把任务容器起好并写 {SPEC}。")
