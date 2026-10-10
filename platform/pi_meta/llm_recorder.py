"""LLM 原始字节录制（借 ARTEX llmrec：含失败 attempt 的原始 wire 字节，可诊断可重放）。

动机：AGENTS.md 里反复出现的 LLM 诊断难题（ai02 端点 1.6s↔244s 抖动、精确 90.4s
超时、DeepSeek 对载荷 500 过滤、qwen 坏 JSON）都是"只有日志碎片没有现场"。
现在每次 chat 调用落盘请求体+原始响应，下次端点发怪直接看字节。

录制策略（成本敏感，不做 ARTEX 式全量全文）：
- 失败（非 200 / 超时 / 网络错误）：请求体（截 LLM_RECORD_REQ_CAP）+ **原始响应字节**
- 成功：精简记录（状态/耗时/模型/n_msg/内容头 2K）——供计量与熔断关联
- 轮转：目录只留最近 LLM_RECORD_KEEP 个文件（默认 500），按文件名（时间前缀）删最旧
- 不写任何 auth header（只录 payload 与响应体）

配置（.env 热加载）：
  LLM_RECORD_ENABLED    默认 1
  LLM_RECORD_DIR        默认 <DATA_DIR>/llm_records
  LLM_RECORD_KEEP       默认 500
  LLM_RECORD_REQ_CAP    请求体上限字符，默认 200000
"""
from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any, Dict, List, Optional

import config

_NAME_RE = re.compile(r"^\d{8}T\d{6}Z_[0-9a-f]{8}_[A-Za-z0-9._-]+_\d{1,4}\.json$")


def _enabled() -> bool:
    return config.env("LLM_RECORD_ENABLED", "1") not in ("0", "false", "False", "")


def _dir() -> str:
    raw = config.env("LLM_RECORD_DIR", "")
    if raw:
        return raw
    return os.path.join(config.DATA_DIR, "llm_records")


def _keep() -> int:
    try:
        return max(10, int(config.env("LLM_RECORD_KEEP", "500")))
    except (TypeError, ValueError):
        return 500


def _req_cap() -> int:
    try:
        return max(1000, int(config.env("LLM_RECORD_REQ_CAP", "200000")))
    except (TypeError, ValueError):
        return 200000


def record_call(*, model: str, host: str, status: Optional[int], elapsed_ms: float,
                payload: Dict[str, Any], response_text: Optional[str], result: str,
                is_success: bool) -> Optional[str]:
    """落一次 chat 调用记录。绝不抛异常（录制故障不得影响主链路）。返回文件名。"""
    try:
        if not _enabled():
            return None
        d = _dir()
        os.makedirs(d, exist_ok=True)
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name = f"{ts}_{uuid.uuid4().hex[:8]}_{model}_{status if status else 0}.json"
        req_cap = _req_cap()
        if is_success:
            # 成功：精简（诊断价值低，留关联字段 + 内容头）
            content_head = (response_text or "")[:2000]
            record = {
                "ts": ts, "model": model, "host": host, "status": status,
                "elapsed_ms": round(elapsed_ms, 1), "result": result,
                "n_messages": len(payload.get("messages") or []),
                "ctx_chars": sum(len(str(m.get("content") or "")) for m in payload.get("messages") or []),
                "response_head": content_head,
            }
        else:
            # 失败：请求体 + 原始响应字节（诊断现场）
            record = {
                "ts": ts, "model": model, "host": host, "status": status,
                "elapsed_ms": round(elapsed_ms, 1), "result": result,
                "request": json.dumps(payload, ensure_ascii=False)[:req_cap],
                "response_raw": (response_text or "")[:20000] if response_text is not None else None,
            }
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False)
        # 索引（列表端点读它，不逐个开大文件）
        try:
            with open(os.path.join(d, "index.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps({"file": name, "ts": ts, "model": model, "host": host,
                                    "status": status, "elapsed_ms": round(elapsed_ms, 1),
                                    "result": result}, ensure_ascii=False) + "\n")
        except Exception:
            pass
        _rotate(d)
        return name
    except Exception:
        return None


def _rotate(d: str) -> None:
    """只留最近 KEEP 个录制文件（index.jsonl 不删，详情 404 无害）。"""
    try:
        files = [n for n in os.listdir(d) if _NAME_RE.match(n)]
        if len(files) <= _keep():
            return
        for n in sorted(files)[:-_keep()]:
            try:
                os.remove(os.path.join(d, n))
            except OSError:
                pass
    except Exception:
        pass


def list_records(limit: int = 30) -> List[Dict[str, Any]]:
    """按时间倒序返回最近 limit 条（读索引，不碰大文件）。"""
    try:
        path = os.path.join(_dir(), "index.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except (ValueError, TypeError):
            continue
        if len(out) >= limit:
            break
    return out


def get_record(name: str) -> Optional[Dict[str, Any]]:
    """按文件名读完整记录（诊断端点用）。"""
    if not _NAME_RE.match(name or ""):
        return None  # 防路径穿越
    try:
        with open(os.path.join(_dir(), name), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


__all__ = ["record_call", "list_records", "get_record"]
