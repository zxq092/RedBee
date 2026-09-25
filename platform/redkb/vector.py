"""RED-KB 向量化:用 bge 端点算语义向量(从 config 读取,密钥不硬编码)。"""
from __future__ import annotations

import os
import struct

import httpx
import sys as _sys

_sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import EMBED_URL, EMBED_KEY, EMBED_MODEL

_DIM = 1024


def enabled() -> bool:
    return bool(EMBED_URL)


def pack(vec: list[float]) -> bytes:
    return struct.pack(f"{len(vec)}f", *vec)


def unpack(blob: bytes) -> list[float]:
    return list(struct.unpack(f"{len(blob)//4}f", blob))


def embed(text: str) -> list[float]:
    """调用 bge 端点返回向量;失败抛异常(调用方决定兜底)。"""
    with httpx.Client(timeout=20) as c:
        r = c.post(f"{EMBED_URL}/embeddings",
                   headers={"Authorization": f"Bearer {EMBED_KEY}"},
                   json={"model": EMBED_MODEL, "input": text[:8000]})
        r.raise_for_status()
        return r.json()["data"][0]["embedding"]


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0
