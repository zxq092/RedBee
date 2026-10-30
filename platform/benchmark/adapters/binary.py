"""Binary-exploitation benchmarks — ExploitGym / ExploitBench / CyberGym.

These evaluate exploit DEVELOPMENT (reverse engineering, pwn, ROP, V8/kernel) in large
Docker images (ExploitBench V8 ~70GB/bug, CyberGym data ~240GB). RedBee 的二进制域能力
（native_* 工具族 + redbee-kali:analy pwntools/gdb/radare2 工具链）已于 2026-10-20 就绪
（gravE2E rung-1 见 adapters/pwnlocal.py），但这三家仍是重量级部署：

- capable()：默认 False；`HINSE_BINARY_READY=1`（或每家专属 HINSE_EXPLOITBENCH_READY 等）
  显式解锁，表示"镜像已拉、spec 已写"。run.py 的 --allow-binary 门槛独立叠加。
- spec: data/benchmark/<name>_targets.json = [{"id","url","desc","flag"?}]

ExploitBench 接入要点（2026-10-20 调研）：
- 官方 harness 自带 agent loop（模型 × 41 V8 bug 环境），env 容器内跑 MCP server
  （接口 rl.mcp.v8_exploit.v1，工具 setup() 学习目标 / grade(...) 按 16 位能力位图判分）。
- ghcr.io/exploitbench/v8-r1:cve-* 预构建镜像，首次使用时拉取。
- 官方 OPENAI_API_BASE/openai/* 路由测的是"模型"不是 RedBee；要让 RedBee 当 agent，
  需要 MCP→TOOL_REGISTRY 桥（把 setup/grade 包成 RedBee 工具）——pwnlocal rung 验证
  native_* 链路后的下一步。
"""
from __future__ import annotations

import os
from pathlib import Path

from ..base import Adapter

SPECS = Path(__file__).resolve().parents[3] / "data" / "benchmark"


def _env_ready(*keys: str) -> bool:
    """能力门槛：默认拒绝；env 显式解锁（表示镜像已拉、spec 已写、验收方式已定）。"""
    for k in keys:
        if str(os.environ.get(k, "")).strip().lower() in ("1", "true", "yes"):
            return True
    return str(os.environ.get("HINSE_BINARY_READY", "")).strip().lower() in ("1", "true", "yes")


class _BinaryAdapter(Adapter):
    category = "binary"
    spec_file = ""

    def list_targets(self) -> list:
        if not self.capable():
            raise SystemExit(f"[{self.name}] 能力未就绪（HINSE_BINARY_READY=1 + --allow-binary 解锁）。")
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
        return _env_ready("HINSE_EXPLOITGYM_READY")

    def describe(self) -> str:
        return ("ExploitGym(UCB)：真实漏洞的利用开发（V8/内核/用户态）。"
                "需拉镜像 + 写 spec + HINSE_EXPLOITGYM_READY=1 + --allow-binary。")


class ExploitBenchAdapter(_BinaryAdapter):
    name = "exploitbench"
    spec_file = "exploitbench_targets.json"

    def capable(self) -> bool:
        return _env_ready("HINSE_EXPLOITBENCH_READY")

    def describe(self) -> str:
        return ("ExploitBench：V8/用户态漏洞的利用阶梯复现（bench-v8 16 能力位 × 41 环境，"
                "ghcr.io/exploitbench/* 镜像，容器内 MCP setup/grade）。"
                "接入需 MCP 桥 + HINSE_EXPLOITBENCH_READY=1 + --allow-binary。")


class CyberGymAdapter(_BinaryAdapter):
    name = "cybergym"
    spec_file = "cybergym_targets.json"

    def capable(self) -> bool:
        return _env_ready("HINSE_CYBERGYM_READY")

    def describe(self) -> str:
        return ("CyberGym(UCB)：真实漏洞分析/利用（数据 ~240GB，纯本地）。"
                "需拉数据 + 写 spec + HINSE_CYBERGYM_READY=1 + --allow-binary。")
