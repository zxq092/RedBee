"""服务部署域 v1（2026-10-21）——把挑战二进制/脚本一键 socat 部署成 TCP 靶标。

复用 cyb-crypto-*/cyb-pwn-overflow 已验证模式：redbee-kali:analy 容器 + socat fork EXEC
+ flag 只写容器内 /flag.txt（工件/源码挂载只读，玩家视角）。

spec: data/benchmark/service_targets.json = [{"id","bin","port","flag","desc","category"}]
  - bin: 宿主机上挑战二进制或 python 脚本路径（ELF 直接 EXEC；.py 用 python3 跑）
  - port: 宿主发布端口

用法：
  python3 -m benchmark.deploy_svc list
  python3 -m benchmark.deploy_svc deploy --id pico19-overflow-1
  python3 -m benchmark.deploy_svc deploy --all
  python3 -m benchmark.deploy_svc stop --id pico19-overflow-1
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import time
from pathlib import Path

SPEC = Path(__file__).resolve().parents[2] / "data" / "benchmark" / "service_targets.json"
IMAGE = "redbee-kali:analy"
PORT_BASE = 19100


def load_spec() -> list[dict]:
    if not SPEC.exists():
        return []
    return json.loads(SPEC.read_text(encoding="utf-8"))


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


def build_deploy_cmd(t: dict, bindir: Path) -> str:
    """容器内启动命令：拷二进制到可写 fs（挂载只读不能 chmod）+ 写 flag + socat。"""
    fname = Path(t["bin"]).name
    if fname.endswith(".py"):
        exec_ = f"python3 /tmp/chal/{fname}"
        copy = f"cp /chal/{fname} /tmp/chal/{fname}"
    else:
        exec_ = f"/tmp/chal/{fname}"
        copy = f"cp /chal/{fname} /tmp/chal/{fname} && chmod +x /tmp/chal/{fname}"
    flag = t.get("flag") or "picoCTF{placeholder}"
    return (f"mkdir -p /tmp/chal && {copy} && "
            f"printf '%s\\n' {shlex.quote(flag)} > /flag.txt && "
            f"exec socat TCP-LISTEN:{t['port']},reuseaddr,fork EXEC:{shlex.quote(exec_)}")


def deploy(t: dict) -> tuple[bool, str]:
    bindir = Path(t["bin"]).parent
    name = f"pico-svc-{t['id']}"
    _docker("rm", "-f", name, check=False)
    cmd = build_deploy_cmd(t, bindir)
    r = _docker("run", "-d", "--name", name,
                "-p", f"{t['port']}:{t['port']}",
                "-v", f"{bindir}:/chal:ro",
                IMAGE, "sh", "-c", cmd, check=False)
    if r.returncode != 0:
        return False, r.stderr.strip()[:200]
    # TCP 探活
    for _ in range(10):
        time.sleep(0.5)
        try:
            import socket
            s = socket.create_connection(("127.0.0.1", int(t["port"])), timeout=3)
            s.close()
            return True, name
        except Exception:
            continue
    return False, f"{name} 起了但 TCP 10s 内不通（看 docker logs {name}）"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("verb", choices=["list", "deploy", "stop"])
    ap.add_argument("--id", default="")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()
    spec = load_spec()
    if not spec:
        print(f"缺 spec {SPEC}")
        return 1
    targets = [t for t in spec if (args.all or t["id"] == args.id) and t.get("bin")]
    if args.verb == "list":
        for t in spec:
            print(f"  {t['id']:<28} :{t.get('port','-'):<6} {t.get('category',''):<12} {Path(t['bin']).name}")
        return 0
    for t in targets:
        if args.verb == "stop":
            _docker("rm", "-f", f"pico-svc-{t['id']}", check=False)
            print(f"stopped {t['id']}")
        else:
            ok, msg = deploy(t)
            print(f"{'✅' if ok else '❌'} {t['id']}: {msg}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
