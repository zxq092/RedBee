"""picoCTF 题库 backend（数据工厂 v1）——离线工件题 + 官方 hints oracle 注入。

spec: data/benchmark/picoctf_tasks.json（benchmark.pico_ingest 生成）
  [{"id","category","points","url","sandbox_url","flag","desc","hints"}]

oracle 提示分级（--hints，工厂提成功率用；轨迹里保留的只有真实交互）：
  0 = 不注 hints（纯净评测）
  1 = 注入官方 hints（默认——rejection sampling 生产的训练数据）
"""
from __future__ import annotations

import json
from pathlib import Path

from ..base import Adapter, sandbox_url_for

SPEC = Path(__file__).resolve().parents[3] / "data" / "benchmark" / "picoctf_tasks.json"
HINTS_LEVEL = 1  # 派发时注入的官方提示条数上限（0=关）


def pico_prompt(cid: str, url: str, sandbox_url: str, desc: str, hints: list) -> str:
    lines = [
        f"【CTF 夺旗 - {cid}】离线工件分析题（picoCTF）。",
        f"挑战文件只读目录（沙箱内可达）: {sandbox_url}",
        f"宿主机等价地址（http_request 工具用）: {url}",
        "做法：",
        "1) 第一步永远是下载工件：沙箱工作目录 curl 列目录 -> 逐个 curl -O 拿全文件"
        "（不要先做端口扫描/侦察——这题只看文件本身）。",
        "2) 通读文件（file/strings/xxd/解压），对照题面判断属于哪类（crypto/forensics/rev/general）。",
        "3) 需要写脚本就用 terminal 的 heredoc 写文件再执行（cat > x.py <<'EOF' ... EOF）；"
        "多行代码不要内联进 python 工具参数。",
        "4) flag 格式 picoCTF{...}。拿到后 submit_finding（poc=关键代码/命令，"
        "evidence=输出原文）然后立即 done 收口。",
        "5) 只做这一道题：拿到 flag 就收口。",
    ]
    clean = [h.strip().lstrip(". ").strip() for h in (hints or []) if h and h.strip().lstrip(". ").strip()]
    if HINTS_LEVEL > 0 and clean:
        lines.append("官方提示（按需使用，能直接用就别绕路）：\n" +
                     "\n".join(f"- {h}" for h in clean[:HINTS_LEVEL]))
    if desc:
        lines.append(f"题面: {desc}")
    return "\n".join(lines)


class PicoAdapter(Adapter):
    name = "picoctf"
    category = "web-ctf"
    # crypto/rev 代码密集 → qwen 稳；forensics/general 走全局（可在 spec 每题覆盖）
    default_model = "qwen3.8-27b"

    def list_targets(self) -> list:
        if not SPEC.exists():
            raise SystemExit(f"[{self.name}] 缺 spec: {SPEC}。先跑 python3 -m benchmark.pico_ingest")
        from .artifact import _ensure_server
        _ensure_server()
        out = []
        for t in json.loads(SPEC.read_text(encoding="utf-8")):
            if not t.get("url") or not t.get("flag"):
                continue
            out.append({"cid": t["id"], "url": t["url"],
                        "desc": t.get("desc", ""), "flag": t["flag"],
                        "hints": t.get("hints", []),
                        "sandbox_url": sandbox_url_for(t.get("sandbox_url") or t["url"]),
                        "model": t.get("model", "") })
        return out

    def objective(self, tgt: dict) -> str:
        return pico_prompt(tgt["cid"], tgt["url"],
                           sandbox_url_for(tgt.get("sandbox_url") or tgt["url"]),
                           tgt.get("desc", ""), tgt.get("hints", []))

    def describe(self) -> str:
        return "picoCTF 题库（数据工厂）：离线工件 + 官方 hints oracle，产出可训练攻击轨迹。"
