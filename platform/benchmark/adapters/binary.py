"""Binary-exploitation benchmarks — ExploitGym / ExploitBench / CyberGym.

These evaluate exploit DEVELOPMENT (reverse engineering, pwn, ROP, V8/kernel) in large
Docker images (ExploitBench V8 ~70GB/bug, CyberGym data ~240GB). RedBee is a Web/CTF-black-box
agent with NO binary-exploit toolchain (no gdb/objdump/ROP/pattern). Running them now would
score ~0 and burn budget — so the adapter is capability-GATED: it refuses to launch RedBee
until a capability flag is passed (--allow-binary) AND a spec file lists the targets.

Add real support later by (a) giving RedBee a binary-exploit executor family, then (b) pulling
the benchmark images and writing data/benchmark/<name>_targets.json.
"""
from __future__ import annotations

from pathlib import Path

from ..base import Adapter

SPECS = Path(__file__).resolve().parents[3] / "data" / "benchmark"


class _BinaryAdapter(Adapter):
    category = "binary"
    spec_file = ""

    def list_targets(self) -> list:
        if not self.capable():
            raise SystemExit(f"[{self.name}] 能力未就绪：RedBee 无二进制利用工具链，拒绝启动。")
        p = SPECS / self.spec_file
        if not p.exists():
            raise SystemExit(f"[{self.name}] 缺目标规格 {p}。请先部署镜像并写该文件。")
        import json
        data = json.loads(p.read_text(encoding="utf-8"))
        return [dict(t, desc=t.get("desc", "")) for t in data if t.get("url")]

    def capable(self) -> bool:
        raise NotImplementedError


class ExploitGymAdapter(_BinaryAdapter):
    name = "exploitgym"
    spec_file = "exploitgym_targets.json"

    def capable(self) -> bool:
        return False  # 需二进制利用能力 + 用户显式放行

    def describe(self) -> str:
        return ("ExploitGym(UCB)：真实漏洞的利用开发（V8/内核/用户态）。"
                "RedBee 现仅 Web，无逆向/pwn 能力；需先扩展二进制工具族 + 显式 --allow-binary。")


class ExploitBenchAdapter(_BinaryAdapter):
    name = "exploitbench"
    spec_file = "exploitbench_targets.json"

    def capable(self) -> bool:
        return False

    def describe(self) -> str:
        return ("ExploitBench：V8/用户态漏洞的利用阶梯复现（bench-v8 16 项）。"
                "RedBee 无二进制利用工具链，默认拒绝；需 --allow-binary + 扩展能力。")


class CyberGymAdapter(_BinaryAdapter):
    name = "cybergym"
    spec_file = "cybergym_targets.json"

    def capable(self) -> bool:
        return False

    def describe(self) -> str:
        return ("CyberGym(UCB)：真实漏洞分析/利用（数据 ~240GB，纯本地）。"
                "RedBee 无二进制利用工具链，默认拒绝；需 --allow-binary + 扩展能力。")
