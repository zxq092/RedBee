"""轻量 Web 鉴权（正式对外用，演示/内网可关闭）。

规则：
- config.WEB_TOKEN 为空 → 不鉴权（内网/演示模式，默认）。
- 非空 → 客户端需先 POST /api/login {"token": <PIMETA_WEB_TOKEN>} 换一个 session token，
  之后写操作带 Authorization: Bearer <session_token>。
- session token = sha256(token + login 时刻 + 盐)，进程内存态，默认 12h 过期。
用恒定时间比较防时序侧信道；不引第三方依赖。
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Dict, Optional

from config import WEB_TOKEN

_SESSION_TTL = float(os.environ.get("PIMETA_WEB_SESSION_TTL", "43200"))  # 12h
_SALT = os.environ.get("PIMETA_WEB_SESSION_SALT", "") or secrets.token_hex(16)
_sessions: Dict[str, float] = {}  # session_token -> expires_at


def auth_enabled() -> bool:
    return bool((WEB_TOKEN or "").strip())


def _cleanup() -> None:
    now = time.time()
    expired = [k for k, v in _sessions.items() if v < now]
    for k in expired:
        _sessions.pop(k, None)


def issue_session(provided: str) -> Optional[str]:
    """校验 PIMETA_WEB_TOKEN，成功签发 session token。恒定时间比较。"""
    expected = (WEB_TOKEN or "").strip()
    if not expected:
        # 未启用鉴权时不签发（调用方应走 auth_enabled 分流）
        return None
    if not isinstance(provided, str) or not hmac.compare_digest(provided.strip(), expected):
        return None
    _cleanup()
    token = secrets.token_urlsafe(32)
    _sessions[token] = time.time() + _SESSION_TTL
    return token


def check_session(token: str) -> bool:
    if not auth_enabled():
        return True
    if not isinstance(token, str) or not token:
        return False
    _cleanup()
    expires = _sessions.get(token)
    if expires is None:
        return False
    if expires < time.time():
        _sessions.pop(token, None)
        return False
    return True
