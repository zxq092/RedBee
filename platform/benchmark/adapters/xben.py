"""XBEN-0x backend — runnable today. Targets = deployed xben-* challenge containers whose
target profile (data/targets/xben-*-24.md) has a reachable `## 地址`."""
from __future__ import annotations

import re
from pathlib import Path

from ..base import Adapter

PROFILES = Path(__file__).resolve().parents[3] / "data" / "targets"


class XbenAdapter(Adapter):
    name = "xben"

    def list_targets(self) -> list:
        targets = []
        for p in sorted(PROFILES.glob("xben-*-24.md")):
            txt = p.read_text(encoding="utf-8")
            m = re.search(r"## 地址\s*\n-\s+(http\S+)", txt)
            if m:
                targets.append({"cid": p.stem, "url": m.group(1).strip(),
                                "desc": "XBEN-0x web challenge"})
        return targets

    def describe(self) -> str:
        return ("自动从 data/targets/xben-*-24.md 的 ## 地址 收集已部署目标。"
                "需先 docker 起对应 XBEN 挑战容器并生成档案。")
