from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from pi_meta import model_runtime as _model_runtime_module
from pi_meta.llm_breaker import BreakerRegistry, classify, get_breaker
from pi_meta.model_runtime import ResolvedRuntime, RuntimeClient, resolve_runtime
from pi_meta.model_runtime import ModelRuntime

_REAL_ASYNC_CLIENT = httpx.AsyncClient


def mock_async_client(handler):
    return lambda *args, **kwargs: _REAL_ASYNC_CLIENT(
        *args,
        transport=httpx.MockTransport(handler),
        **{k: v for k, v in kwargs.items() if k != "transport"},
    )


def iso(base: datetime) -> str:
    return base.isoformat()


class FakeClock:
    def __init__(self):
        self.now = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> str:
        return iso(self.now)

    def advance(self, seconds: float):
        self.now = self.now + timedelta(seconds=seconds)


# ---- 分类 ----

def test_classify_hard_soft_none():
    assert classify(401, "") == "hard"
    assert classify(402, "") == "hard"
    assert classify(403, "") == "hard"
    assert classify(404, "") == "hard"
    assert classify(None, "AUTH_ERROR") == "hard"
    assert classify(None, "NOT_FOUND") == "hard"
    assert classify(429, "") == "soft"
    assert classify(500, "") == "soft"
    assert classify(503, "") == "soft"
    assert classify(None, "TIMEOUT") == "soft"
    assert classify(None, "NETWORK_ERROR") == "soft"
    assert classify(None, "RATE_LIMIT") == "soft"
    assert classify(400, "") is None
    assert classify(None, "PARSE_ERROR") is None
    assert classify(None, "HTTP_400") is None


# ---- 硬失败：一次即熔断 ----

def test_hard_failure_trips_immediately_and_blocks_until_cooldown():
    clock = FakeClock()
    reg = BreakerRegistry(now_fn=clock)
    assert reg.try_admit("m1") == (True, "ok")
    action = reg.record_failure("m1", 401, "")
    assert action == "hard-trip"
    assert reg.try_admit("m1") == (False, "tripped")
    clock.advance(1799)
    assert reg.try_admit("m1")[0] is False
    clock.advance(2)  # 30min 硬冷却到
    assert reg.try_admit("m1") == (True, "half-open")


def test_hard_trip_keeps_trip_count_and_success_resets():
    clock = FakeClock()
    reg = BreakerRegistry(now_fn=clock)
    reg.record_failure("m1", 403, "")
    reg.record_success("m1")
    assert reg.try_admit("m1") == (True, "ok")
    status = reg.status()["m1"]
    assert status["state"] == "ok"
    assert status["consecutive_soft"] == 0
    assert status["trip_count"] == 1  # 梯度计数保留


# ---- 软失败：连续 N 次熔断，冷却梯度 ----

def test_soft_failure_counts_and_trips_at_threshold(monkeypatch):
    clock = FakeClock()
    reg = BreakerRegistry(now_fn=clock)
    assert reg.record_failure("m1", 429, "") == "soft-count"
    assert reg.try_admit("m1")[0] is True
    assert reg.record_failure("m1", 503, "") == "soft-count"
    assert reg.try_admit("m1")[0] is True
    assert reg.record_failure("m1", 500, "") == "soft-trip"
    assert reg.try_admit("m1") == (False, "tripped")
    clock.advance(61)  # 第一次软熔断冷却 60s
    assert reg.try_admit("m1") == (True, "half-open")


def test_soft_cooldown_gradient_escalates_with_trip_count(monkeypatch):
    clock = FakeClock()
    reg = BreakerRegistry(now_fn=clock)
    monkeypatch.setenv("LLM_BREAKER_SOFT_TRIPS", "2")
    # 第 1 次熔断 → 60s
    reg.record_failure("m1", 429, "")
    reg.record_failure("m1", 429, "")
    assert reg.status()["m1"]["trip_count"] == 1
    clock.advance(61)
    assert reg.try_admit("m1")[0] is True
    # 半开后又连 2 次软失败 → 第 2 次熔断 → 300s
    reg.record_failure("m1", 429, "")
    reg.record_failure("m1", 429, "")
    assert reg.status()["m1"]["trip_count"] == 2
    assert reg.try_admit("m1")[0] is False
    clock.advance(299)
    assert reg.try_admit("m1")[0] is False
    clock.advance(2)
    assert reg.try_admit("m1")[0] is True


def test_success_resets_soft_counter_without_tripping(monkeypatch):
    monkeypatch.setenv("LLM_BREAKER_SOFT_TRIPS", "3")
    clock = FakeClock()
    reg = BreakerRegistry(now_fn=clock)
    reg.record_failure("m1", 429, "")
    reg.record_success("m1")
    reg.record_failure("m1", 429, "")
    assert reg.try_admit("m1")[0] is True
    assert reg.status()["m1"]["consecutive_soft"] == 1


def test_manual_reset_clears_everything():
    clock = FakeClock()
    reg = BreakerRegistry(now_fn=clock)
    reg.record_failure("m1", 401, "")
    assert reg.try_admit("m1")[0] is False
    reg.reset("m1")
    assert reg.try_admit("m1") == (True, "ok")
    status = reg.status()["m1"]
    assert status["state"] == "ok"
    assert status["trip_count"] == 0
    assert status["cooldown_until"] is None


def test_disabled_breaker_is_pass_through(monkeypatch):
    monkeypatch.setenv("LLM_BREAKER_ENABLED", "0")
    reg = BreakerRegistry()
    assert reg.record_failure("m1", 401, "") is None
    assert reg.try_admit("m1") == (True, "disabled")


# ---- 持久化（跨进程/重启恢复） ----

def test_state_persists_across_registry_instances():
    clock = FakeClock()
    reg1 = BreakerRegistry(now_fn=clock)
    reg1.record_failure("persist-model", 401, "")
    # 模拟网关重启：新实例从同一 DB 恢复
    reg2 = BreakerRegistry(now_fn=clock)
    assert reg2.try_admit("persist-model") == (False, "tripped")
    row = reg2.status()["persist-model"]
    assert row["state"] == "tripped"
    assert row["last_error_code"]


# ---- RuntimeClient.chat 集成 ----

def _profiles_env(monkeypatch):
    monkeypatch.setenv("MODEL_PRIORITY", "first,second")
    monkeypatch.setenv("MODEL_BASE_URL", "http://first.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "secret")
    monkeypatch.setenv("MODEL_PROFILE_JSON", json.dumps({
        "models": {
            "first": {"base_url": "http://first.test/v1", "auth_ref": "FAKE_MODEL_KEY"},
            "second": {"base_url": "http://second.test/v1", "auth_ref": "FAKE_MODEL_KEY"},
        }
    }))


@pytest.mark.asyncio
async def test_chat_401_on_primary_trips_and_fails_over_to_secondary(monkeypatch):
    hosts = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(str(request.url.host))
        if str(request.url.host) == "first.test":
            return httpx.Response(401, request=request)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "ok", "tool_calls": []}}]},
            request=request,
        )

    _profiles_env(monkeypatch)
    monkeypatch.setattr("pi_meta.model_runtime.httpx.AsyncClient", mock_async_client(handler))
    resolution = await resolve_runtime()
    assert resolution.ok
    result = await RuntimeClient.chat(resolution.runtime, {"messages": []})
    assert result.ok
    assert result.content == "ok"
    assert "second.test" in hosts
    assert not get_breaker().try_admit("first")[0]
    assert get_breaker().try_admit("second")[0]


@pytest.mark.asyncio
async def test_chat_429_exhaust_retries_then_trips_after_threshold(monkeypatch):
    """软失败：单候选重试 3 次后记 1 次软失败（不是 3 次），阈值内不熔断。"""
    chat_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal chat_calls
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": []}, request=request)
        chat_calls += 1
        return httpx.Response(429, request=request)

    _profiles_env(monkeypatch)
    monkeypatch.setenv("LLM_BREAKER_SOFT_TRIPS", "3")
    monkeypatch.setattr("pi_meta.model_runtime.httpx.AsyncClient", mock_async_client(handler))
    resolution = await resolve_runtime()
    # 每次 chat：first 重试 3 次失败（记 1 次软失败）→ 降级 second 再 3 次
    result = await RuntimeClient.chat(resolution.runtime, {"messages": []})
    assert not result.ok
    assert result.error.code == "NO_RUNTIME"
    assert chat_calls == 6
    assert get_breaker().status()["first"]["consecutive_soft"] == 1
    # 第二次 chat：first 软计数到 2，仍放行重试
    result = await RuntimeClient.chat(resolution.runtime, {"messages": []})
    assert not result.ok
    assert chat_calls == 12
    assert get_breaker().status()["first"]["consecutive_soft"] == 2
    # 第三次：first 软计数到 3 → 熔断
    result = await RuntimeClient.chat(resolution.runtime, {"messages": []})
    assert not result.ok
    assert get_breaker().try_admit("first") == (False, "tripped")


@pytest.mark.asyncio
async def test_resolver_skips_tripped_model_without_probing(monkeypatch):
    """首选已熔断冷却中 → 解析阶段直接跳过，不浪费探测往返。"""
    get_breaker().record_failure("first", 401, "")
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url.host))
        return httpx.Response(200, json={"data": []}, request=request)

    _profiles_env(monkeypatch)
    monkeypatch.setattr("pi_meta.model_runtime.httpx.AsyncClient", mock_async_client(handler))
    resolution = await resolve_runtime()
    assert resolution.ok
    assert resolution.runtime.runtime.model == "second"
    assert resolution.runtime.degraded_from == "first"
    assert calls == ["second.test"]  # first 被熔断器拦下，没探


@pytest.mark.asyncio
async def test_all_tripped_still_probes_chain_head(monkeypatch):
    """全灭兜底：所有候选都在冷却中，仍打链首（half-open 试探）。"""
    get_breaker().record_failure("first", 401, "")
    get_breaker().record_failure("second", 401, "")
    chat_hosts = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/models"):
            return httpx.Response(503, request=request)
        chat_hosts.append(str(request.url.host))
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "ok", "tool_calls": []}}]},
            request=request,
        )

    _profiles_env(monkeypatch)
    monkeypatch.setattr("pi_meta.model_runtime.httpx.AsyncClient", mock_async_client(handler))
    # 解析阶段：两候选都熔断跳过 → NO_RUNTIME
    resolution = await resolve_runtime()
    assert not resolution.ok
    assert resolution.error.code == "NO_RUNTIME"

    # chat 阶段：手工构造含两候选的 resolved 快照（模拟旧任务持有的运行时）
    rt1 = ModelRuntime("first", "http://first.test/v1", "FAKE_MODEL_KEY", 5, 2, "/v1/models", "t")
    rt2 = ModelRuntime("second", "http://second.test/v1", "FAKE_MODEL_KEY", 5, 2, "/v1/models", "t")
    resolved = ResolvedRuntime(
        runtime=rt1, candidate_runtimes=[rt1, rt2], available_indices=[0, 1],
        selected_index=0, degraded_from=None, degraded_chain=["first", "second"],
        runtime_id="rt-test", health_checked_at="2026-10-09T00:00:00+00:00",
        probe_status="healthy", probe_error_code=None,
    )
    result = await RuntimeClient.chat(resolved, {"messages": []})
    assert result.ok
    assert chat_hosts == ["first.test"]  # 兜底打链首


@pytest.mark.asyncio
async def test_success_through_chat_heals_breaker(monkeypatch):
    get_breaker().record_failure("first", 429, "")
    get_breaker().record_failure("first", 429, "")

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url.host) == "first.test":
            return httpx.Response(
                200, json={"choices": [{"message": {"content": "ok", "tool_calls": []}}]},
                request=request,
            )
        return httpx.Response(503, request=request)

    _profiles_env(monkeypatch)
    monkeypatch.setattr("pi_meta.model_runtime.httpx.AsyncClient", mock_async_client(handler))
    resolution = await resolve_runtime()
    assert resolution.ok
    result = await RuntimeClient.chat(resolution.runtime, {"messages": []})
    assert result.ok
    assert get_breaker().status()["first"]["state"] == "ok"
    assert get_breaker().status()["first"]["consecutive_soft"] == 0
