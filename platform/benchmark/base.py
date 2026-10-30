"""Benchmark adapter base: share the "drive RedBee as agent through the gateway" machinery
across every benchmark backend. Pure-additive harness layer — never touches the engine.

A benchmark = an Adapter subclass providing:
  - name / category ("web-ctf" runnable today, "binary" gated on capability)
  - list_targets() -> List[{cid, url, desc}]  (where the challenge lives / may be reached)
  - capable(flags) -> bool   (binary benchmarks refuse unless capability is added)
The shared driver dispatches RedBee in ctf/objective mode, waits for the task to reach `done`
(never cancels, so RED-KB reflow fires), extracts a flag, and aggregates a score.
"""
from __future__ import annotations

import re
import time
from typing import List

import httpx

GATEWAY = "http://127.0.0.1:8100"
POLL_S = 8
FLAG_RE = re.compile(
    r"(?:HTB|FLAG|GCTF|SEKAI|CTF|picoCTF|hkcert2{0,2}|HKN|Glacier|DUCTF)\{[^}\s]{4,}\}",
    re.IGNORECASE,
)
# nilgiri 等靶场的 flag 是 UUIDv4（无前缀形态），判分时一并提取
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)


def objective_prompt(cid: str, url: str, desc: str = "") -> str:
    base = (
        f"【CTF 夺旗 - {cid}】target={url}\n"
        "目标是一个 flag，藏在靶场的 anomalous data / 特殊文件 / 隐藏记录里。\n"
        "读数据本身（表/列表/响应体/特殊名字/编码串）先于 JS/参数/状态码，追每条异常到端。\n"
        "拿到 flag 用 submit_finding 提交（evidence 含原始响应），然后立即收口——不要继续猎更多漏洞。"
    )
    return f"{base}\n题面提示: {desc}" if desc else base


_GW_CACHE = ""


def host_gateway_ip() -> str:
    """沙箱容器可达的宿主机地址（docker0 默认网桥的网关 IP）。

    优先级：HINSE_SANDBOX_HOSTGW env > `docker network inspect bridge` 的 gateway
    > 172.17.0.1 兜底。不能无条件写死 172.17.0.1：本机 daemon.json bip=192.168.71.3/24，
    docker0 网关是 192.168.71.3；172.17.0.1 只是残留空网络（cve-2017-7529_default）
    上宿主持有的地址，随时可能被 docker network rm 清掉。
    """
    global _GW_CACHE
    import os as _os
    import subprocess as _sp
    override = _os.environ.get("HINSE_SANDBOX_HOSTGW", "").strip()
    if override:
        return override
    if _GW_CACHE:
        return _GW_CACHE
    try:
        out = _sp.run(
            ["docker", "network", "inspect", "bridge",
             "--format", "{{(index .IPAM.Config 0).Gateway}}"],
            capture_output=True, text=True, timeout=15,
        ).stdout.strip()
        if out:
            _GW_CACHE = out
            return out
    except Exception:
        pass
    return "172.17.0.1"


def sandbox_url_for(url: str) -> str:
    """把 URL 的 host 部分改写为沙箱可达的宿主网关（127.0.0.1/localhost/旧网关 172.17.0.1 → 当前网关）。"""
    gw = host_gateway_ip()
    for h in ("127.0.0.1", "localhost", "172.17.0.1"):
        url = url.replace(f"://{h}", f"://{gw}")
    return url


class Adapter:
    name = ""
    category = "web-ctf"  # or "binary"

    def list_targets(self) -> List[dict]:
        raise NotImplementedError

    def describe(self) -> str:
        return ""

    def capable(self) -> bool:
        """binary 基准当前返回 False：RedBee 是 Web/CTF agent，无二进制利用能力。"""
        return True

    def objective(self, tgt: dict) -> str:
        """派发文案；子类可覆盖（如 artifact 后端的下载+脚本分析指令）。"""
        return objective_prompt(tgt["cid"], tgt["url"], tgt.get("desc", ""))


def _client(gateway: str, token: str = ""):
    hdrs = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.Client(base_url=gateway, headers=hdrs, timeout=30)


def dispatch(adapter: Adapter, tgt: dict, client: httpx.Client, session_prefix: str, budget_s: int,
             model: str = "", dump_trajectory: bool = False) -> str:
    cid, url = tgt["cid"], tgt["url"]
    # 按域模型路由（2026-10-21）：CLI --model > spec 每题 "model" > backend default_model > 全局。
    # 实测依据：web 多步题 DeepSeek 轮次 3-5×（locktalk 218 轮 vs qwen 87 轮）；
    # pwn/crypto 代码密集题 qwen 稳（DeepSeek 长代码参数序列化连败）。
    m = (model or tgt.get("model") or getattr(adapter, "default_model", "") or "").strip()
    body = {
        "session_id": f"{session_prefix}-{cid}-{int(time.time())}",
        "target": url,
        "target_id": cid,
        "task": adapter.objective(tgt),
        "params": {"mode": "ctf", "task_budget": budget_s},  # 目标猎取 + 引擎预算对齐(收口 done)
    }
    if m:
        body["params"]["model"] = m
    plan = tgt.get("plan") or []
    if isinstance(plan, list) and plan:
        body["params"]["steps"] = plan  # 分步执行（引擎顺序子任务）：spec 每题可选 plan=[{name,prompt,wait_s}]
    if dump_trajectory:
        body["params"]["dump_trajectory"] = True
    r = client.post("/api/task", json=body)
    r.raise_for_status()
    return r.json()["task_id"]


def receive_done(task_id: str, client: httpx.Client, budget_s: int) -> tuple[str, float]:
    """轮询到终态；**绝不 cancel**（done 才触发 KB 回流）。返回 (status, elapsed_s)。"""
    max_wait = budget_s + 300  # 给引擎 finalize/report 留余量
    t0 = time.time()
    while time.time() - t0 < max_wait:
        try:
            status = client.get(f"/api/task/{task_id}/meta").json().get("status", "")
        except Exception:
            status = ""
        if status in ("done", "runtime_error", "cancelled", "error"):
            return status, time.time() - t0
        time.sleep(POLL_S)
    return "timeout", max_wait


def extract_flag(task_id: str, client: httpx.Client) -> list:
    r = client.get(f"/api/task/{task_id}/board")
    if r.status_code != 200:
        return []
    flags, seen = [], set()
    try:
        findings = r.json().get("findings", [])
    except Exception:
        findings = []
    for f in findings:
        blob = f"{f.get('title','')} {f.get('poc','')} {f.get('evidence','')}"
        m = FLAG_RE.search(blob)
        if m and m.group(0) not in seen:
            seen.add(m.group(0))
            flags.append(m.group(0))
        for u in UUID_RE.findall(blob):
            if u.lower() not in seen:
                seen.add(u.lower())
                flags.append(u)
    return flags


def board_findings(task_id: str, client: httpx.Client) -> int:
    try:
        return len(client.get(f"/api/task/{task_id}/board").json().get("findings", []))
    except Exception:
        return 0


def run_target(adapter: Adapter, tgt: dict, client: httpx.Client, opts) -> dict:
    cid = tgt["cid"]
    task_id = dispatch(adapter, tgt, client, opts.session_prefix, opts.timeout_min * 60,
                       getattr(opts, "model", "") or "")
    status, elapsed = receive_done(task_id, client, opts.timeout_min * 60)
    flags = extract_flag(task_id, client)
    known = (tgt.get("flag") or "").strip()
    if known:
        solved = any(known == f.strip() or known in f for f in flags)
    else:
        solved = bool(flags)
    return {
        "id": cid, "url": tgt["url"], "task_id": task_id,
        "status": status, "solved": solved, "flags": flags,
        "findings": board_findings(task_id, client),
        "elapsed_s": round(elapsed, 1),
    }


def run_suite(adapter: Adapter, client: httpx.Client, opts) -> List[dict]:
    targets = adapter.list_targets()
    ids = {x.strip() for x in (opts.ids or "").split(",") if x.strip()}
    if ids:
        targets = [t for t in targets if t["cid"] in ids]
    if not targets:
        raise SystemExit(f"[{adapter.name}] 无目标（ids 过滤后为空）。{adapter.describe()}")
    return [run_target(adapter, t, client, opts) for t in targets]


def score(results: List[dict]) -> dict:
    solved = sum(1 for r in results if r.get("solved"))
    times = [r["elapsed_s"] for r in results if r.get("elapsed_s")]
    return {"solved": solved, "total": len(results),
            "avg_s": round(sum(times) / len(times), 1) if times else 0.0}
