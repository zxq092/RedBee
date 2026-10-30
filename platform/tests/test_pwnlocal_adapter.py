"""pwnlocal 适配器（gravE2E rung-1）单测：注册/门槛/prompt 要素/网关地址推导。

不依赖真实容器与 spec 文件（构造 synthetic target 验证 prompt 与地址改写）。
"""
import pytest

from benchmark.adapters import BACKENDS, get_adapter
from benchmark.base import sandbox_url_for


def test_registered_and_gate_semantics():
    assert "pwnlocal" in BACKENDS
    a = get_adapter("pwnlocal")
    assert a.name == "pwnlocal"
    # 自建靶标能力已就绪（区别于 exploitgym/exploitbench/cybergym 的 False）
    assert a.capable() is True
    # category=binary → run.py 仍要求 --allow-binary 显式放行（门槛语义不变）


def test_prompt_loads_skill_and_tooling(monkeypatch):
    from benchmark.adapters import pwnlocal
    a = get_adapter("pwnlocal")
    tgt = {"cid": "cyb-pwn-overflow", "url": "http://127.0.0.1:19051",
           "desc": "stack overflow", "flag": "flag{x}",
           "sandbox_url": "http://127.0.0.1:19051"}
    txt = a.objective(tgt)
    # 必须引导先解锁工具族，否则 CTF objective 模式下 native_* 不可见
    assert "load_skill('binary-exploitation')" in txt
    for kw in ("native_info", "native_pwn", "pwntools", "submit_finding"):
        assert kw in txt
    # 真值 flag 绝不进 prompt
    assert "flag{x}" not in txt


def test_prompt_addresses_use_derived_gateway(monkeypatch):
    monkeypatch.setenv("HINSE_SANDBOX_HOSTGW", "10.1.2.3")
    from benchmark.base import _GW_CACHE
    import benchmark.base as bb
    monkeypatch.setattr(bb, "_GW_CACHE", "")  # 清缓存，env 生效
    a = get_adapter("pwnlocal")
    tgt = {"cid": "t", "url": "http://127.0.0.1:19051", "desc": "",
           "sandbox_url": "http://127.0.0.1:19051"}
    txt = a.objective(tgt)
    assert "10.1.2.3:19051" in txt
    assert "127.0.0.1:19051" in txt  # 宿主等价地址保留


def test_sandbox_url_rewrite_variants():
    assert sandbox_url_for("http://127.0.0.1:8901/x/") .startswith("http://")
    # 旧网关硬编码值也被归一到当前网关（host 部分替换，路径端口不动）
    import re
    out = sandbox_url_for("http://172.17.0.1:8901/cyb-1/challenge/")
    m = re.match(r"http://([0-9.]+):8901/cyb-1/challenge/", out)
    assert m and m.group(1) not in ("127.0.0.1", "172.17.0.1")
