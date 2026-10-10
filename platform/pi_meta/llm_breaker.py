"""LLM 熔断器（借 ARTEX llmpool：安全窗口 failover + 进程级熔断落库）。

硬失败（401/402/403/404 认证/余额/端点不存在，及 AUTH_ERROR/NOT_FOUND 探测码）
→ 一次即熔断，默认冷却 30min；软失败（429/5xx/超时/网络）→ 连续 N 次（默认 3）
熔断，冷却梯度 1/5/30min（按累计熔断次数取档）。成功 → 清软失败计数、恢复 ok。

状态落 pimeta.db `llm_breakers` 表 → 网关重启后从库恢复，不重新挨一遍故障模型的痛。
非流式 chat 是原子的（任何失败都没吐过 token = 安全窗口内），换模型不会产生
重复输出——这是"吐过 token 绝不切换"铁律在我们非流式路径下的自然满足。

配置（.env 热加载）：
  LLM_BREAKER_ENABLED        默认 1
  LLM_BREAKER_SOFT_TRIPS     软失败熔断阈值，默认 3
  LLM_BREAKER_HARD_COOLDOWN  硬失败冷却秒，默认 1800
  LLM_BREAKER_SOFT_COOLDOWNS 软失败冷却梯度（逗号分隔秒），默认 "60,300,1800"
"""
from __future__ import annotations

import sqlite3
from typing import Dict, Optional, Tuple

import config
from .sessions import _connect, utcnow

_SCHEMA = """CREATE TABLE IF NOT EXISTS llm_breakers (
  model TEXT PRIMARY KEY,
  state TEXT NOT NULL DEFAULT 'ok',
  consecutive_soft INTEGER NOT NULL DEFAULT 0,
  trip_count INTEGER NOT NULL DEFAULT 0,
  cooldown_until TEXT,
  last_trip_at TEXT,
  last_success_at TEXT,
  last_error_code TEXT,
  updated_at TEXT
)"""

_HARD_STATUS = {401, 402, 403, 404}
_SOFT_STATUS = {429} | set(range(500, 600))
_HARD_CODE = {"AUTH_ERROR", "NOT_FOUND"}
_SOFT_CODE = {"RATE_LIMIT", "SERVER_ERROR", "TIMEOUT", "NETWORK_ERROR", "PROBE_ERROR"}


def _soft_trips() -> int:
    try:
        return max(1, int(config.env("LLM_BREAKER_SOFT_TRIPS", "3")))
    except (TypeError, ValueError):
        return 3


def _hard_cooldown() -> float:
    try:
        return max(1.0, float(config.env("LLM_BREAKER_HARD_COOLDOWN", "1800")))
    except (TypeError, ValueError):
        return 1800.0


def _soft_cooldowns() -> list[float]:
    raw = config.env("LLM_BREAKER_SOFT_COOLDOWNS", "60,300,1800")
    try:
        values = [max(1.0, float(x)) for x in raw.split(",") if x.strip()]
    except (TypeError, ValueError):
        values = []
    return values or [60.0, 300.0, 1800.0]


def classify(status: Optional[int], code: str) -> Optional[str]:
    """错误分类：'hard'/'soft'/None（None = 与模型可用性无关，不动熔断状态）。"""
    if status in _HARD_STATUS:
        return "hard"
    if status in _SOFT_STATUS:
        return "soft"
    code = (code or "").upper()
    if code in _HARD_CODE:
        return "hard"
    if code in _SOFT_CODE:
        return "soft"
    return None


class BreakerRegistry:
    """每模型一个熔断状态；内存无缓存，每次操作直读/写库（SQLite 单文件，开销可忽略）。"""

    def __init__(self, now_fn=None) -> None:
        self._now = now_fn or utcnow

    @staticmethod
    def _conn() -> sqlite3.Connection:
        conn = _connect()
        conn.execute(_SCHEMA)
        conn.commit()
        return conn

    @staticmethod
    def enabled() -> bool:
        # 调用时属性查找（config.env 热加载语义；测试中 conftest 对该属性打桩）
        return config.env("LLM_BREAKER_ENABLED", "1") not in ("0", "false", "False", "")

    def _row(self, conn: sqlite3.Connection, model: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM llm_breakers WHERE model=?", (model,)).fetchone()
        if row is None:
            return {
                "model": model, "state": "ok", "consecutive_soft": 0, "trip_count": 0,
                "cooldown_until": None, "last_trip_at": None, "last_success_at": None,
                "last_error_code": None, "updated_at": None,
            }
        return dict(row)

    @staticmethod
    def _upsert(conn: sqlite3.Connection, model: str, *, state: str, consecutive_soft: int,
                trip_count: int, cooldown_until, last_trip_at, last_success_at=None,
                last_error_code=None) -> None:
        conn.execute(
            """INSERT INTO llm_breakers (model, state, consecutive_soft, trip_count,
                  cooldown_until, last_trip_at, last_success_at, last_error_code, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(model) DO UPDATE SET
                 state=excluded.state, consecutive_soft=excluded.consecutive_soft,
                 trip_count=excluded.trip_count, cooldown_until=excluded.cooldown_until,
                 last_trip_at=excluded.last_trip_at, last_success_at=excluded.last_success_at,
                 last_error_code=excluded.last_error_code, updated_at=excluded.updated_at""",
            (model, state, consecutive_soft, trip_count, cooldown_until, last_trip_at,
             last_success_at, last_error_code, utcnow()),
        )

    def try_admit(self, model: str) -> Tuple[bool, str]:
        """是否允许尝试该模型：ok→放行；tripped 且冷却中→拦；冷却已过→half-open 放行试探。"""
        if not self.enabled():
            return True, "disabled"
        now = self._now()
        conn = self._conn()
        try:
            row = self._row(conn, model)
        finally:
            conn.close()
        if row["state"] != "tripped":
            return True, "ok"
        if row["cooldown_until"] and row["cooldown_until"] > now:
            return False, "tripped"
        return True, "half-open"

    def record_failure(self, model: str, status: Optional[int], code: str) -> Optional[str]:
        """记录一次失败，返回动作（'hard-trip'/'soft-trip'/'soft-count'/None）。"""
        kind = classify(status, code)
        if kind is None or not self.enabled():
            return None
        now = self._now()
        conn = self._conn()
        try:
            row = self._row(conn, model)
            trip_count = int(row["trip_count"] or 0)
            if kind == "hard":
                trip_count += 1
                cooldown = _hard_cooldown()
                self._upsert(conn, model, state="tripped", consecutive_soft=0,
                             trip_count=trip_count, cooldown_until=_advance(now, cooldown),
                             last_trip_at=now, last_error_code=code or f"HTTP_{status}")
                conn.commit()
                return "hard-trip"
            soft = int(row["consecutive_soft"] or 0) + 1
            if soft >= _soft_trips():
                trip_count += 1
                ladder = _soft_cooldowns()
                cooldown = ladder[min(trip_count - 1, len(ladder) - 1)]
                self._upsert(conn, model, state="tripped", consecutive_soft=0,
                             trip_count=trip_count, cooldown_until=_advance(now, cooldown),
                             last_trip_at=now, last_error_code=code or f"HTTP_{status}")
                conn.commit()
                return "soft-trip"
            self._upsert(conn, model, state=row["state"], consecutive_soft=soft,
                         trip_count=trip_count, cooldown_until=row["cooldown_until"],
                         last_trip_at=row["last_trip_at"], last_error_code=code or f"HTTP_{status}")
            conn.commit()
            return "soft-count"
        finally:
            conn.close()

    def record_success(self, model: str) -> None:
        """成功一次：恢复 ok、清软失败计数（保留 trip_count 供冷却梯度继续升档）。"""
        if not self.enabled():
            return
        now = self._now()
        conn = self._conn()
        try:
            row = self._row(conn, model)
            if row["state"] == "ok" and not int(row["consecutive_soft"] or 0):
                return
            self._upsert(conn, model, state="ok", consecutive_soft=0,
                         trip_count=int(row["trip_count"] or 0), cooldown_until=None,
                         last_trip_at=row["last_trip_at"], last_success_at=now,
                         last_error_code=row["last_error_code"])
            conn.commit()
        finally:
            conn.close()

    def reset(self, model: str) -> None:
        """人工复位（运维端点）：清计数、清熔断。"""
        now = self._now()
        conn = self._conn()
        try:
            self._upsert(conn, model, state="ok", consecutive_soft=0, trip_count=0,
                         cooldown_until=None, last_trip_at=None, last_success_at=None,
                         last_error_code=None)
            conn.commit()
        finally:
            conn.close()

    def status(self) -> Dict[str, Dict[str, object]]:
        """全量状态（/api/llm/breakers 展示用）。"""
        conn = self._conn()
        try:
            rows = conn.execute("SELECT * FROM llm_breakers ORDER BY model").fetchall()
        finally:
            conn.close()
        now = self._now()
        out: Dict[str, Dict[str, object]] = {}
        for row in rows:
            d = dict(row)
            tripped = d["state"] == "tripped" and bool(d["cooldown_until"]) and d["cooldown_until"] > now
            d["effectively_tripped"] = tripped
            out[d["model"]] = d
        return out


def _advance(now_iso: str, seconds: float) -> str:
    """ISO 时间 + 秒（与 utcnow() 同格式，字符串比较即时间比较）。"""
    from datetime import datetime, timedelta, timezone
    base = datetime.fromisoformat(now_iso)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    return (base + timedelta(seconds=seconds)).isoformat()


_registry: Optional[BreakerRegistry] = None


def get_breaker() -> BreakerRegistry:
    global _registry
    if _registry is None:
        _registry = BreakerRegistry()
    return _registry


__all__ = ["BreakerRegistry", "classify", "get_breaker"]
