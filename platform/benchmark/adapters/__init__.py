"""Benchmark adapters registry."""
from __future__ import annotations

from ..base import Adapter
from .xben import XbenAdapter
from .cybench import CybenchAdapter
from .artifact import ArtifactAdapter
from .cybservice import CybenchServiceAdapter
from .pwnlocal import PwnLocalAdapter
from .picoctf import PicoAdapter
from .nilgiri import NilgiriAdapter
from .binary import ExploitGymAdapter, ExploitBenchAdapter, CyberGymAdapter

BACKENDS = {
    "xb": XbenAdapter,
    "xben": XbenAdapter,
    "cybench": CybenchAdapter,
    "cybartifact": ArtifactAdapter,
    "artifact": ArtifactAdapter,
    "cybservice": CybenchServiceAdapter,
    "pwnlocal": PwnLocalAdapter,
    "picoctf": PicoAdapter,
    "nilgiri": NilgiriAdapter,
    "pico": PicoAdapter,
    "pwngym": PwnLocalAdapter,
    "exploitgym": ExploitGymAdapter,
    "exploitbench": ExploitBenchAdapter,
    "cybergym": CyberGymAdapter,
}


def get_adapter(name: str) -> Adapter:
    cls = BACKENDS.get(str(name).strip().lower())
    if cls is None:
        raise SystemExit(f"未知 benchmark: {name!r}。可用: {', '.join(BACKENDS)}")
    return cls()
