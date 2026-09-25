from __future__ import annotations

import asyncio
import json
import os
from dataclasses import fields, is_dataclass

import httpx
import pytest

import config
from pi_meta import model_runtime as _model_runtime_module


_REAL_ASYNC_CLIENT = httpx.AsyncClient


def mock_async_client(handler):
    return lambda *args, **kwargs: _REAL_ASYNC_CLIENT(
        *args,
        transport=httpx.MockTransport(handler),
        **{k: v for k, v in kwargs.items() if k != "transport"},
    )
from pi_meta.model_runtime import (
    AgentResult,
    ChatResult,
    DispatchResult,
    ExtractionResult,
    ModelRuntime,
    ModelRuntimeError,
    PlanResult,
    ResolvedRuntime,
    RuntimeClient,
    RuntimeResolution,
    resolve_runtime,
)


def runtime(model: str = "qwen3.8-27b", base_url: str = "http://model.test/v1") -> ModelRuntime:
    return ModelRuntime(
        model=model,
        base_url=base_url,
        auth_ref="FAKE_MODEL_KEY",
        timeout=5,
        read_timeout=2,
        health_path="/v1/models",
        config_version="test-1",
    )


def resolved(r: ModelRuntime, *candidates: ModelRuntime, selected: int = 0) -> ResolvedRuntime:
    candidates = list(candidates) or [r]
    return ResolvedRuntime(
        runtime=r,
        candidate_runtimes=candidates,
        available_indices=[selected],
        selected_index=selected,
        degraded_from=None,
        degraded_chain=[],
        runtime_id=f"runtime-{r.model}",
        health_checked_at="2026-09-17T00:00:00+00:00",
        probe_status="healthy",
        probe_error_code=None,
    )


@pytest.mark.asyncio
async def test_config_priority_fallback_deduplicate_and_module_alias(monkeypatch):
    monkeypatch.setenv("MODEL_PRIORITY", " qwen3.8-27b, DeepSeek-V4-Flash, qwen3.8-27b ")
    monkeypatch.setenv("MODEL_FALLBACKS", " qwen3.8-27b, other-model ")
    assert config.model_priority() == ["qwen3.8-27b", "DeepSeek-V4-Flash", "other-model"]
    assert config.MODEL_PRIORITY == config.model_priority()


@pytest.mark.asyncio
async def test_config_rejects_empty_priority(monkeypatch):
    monkeypatch.setenv("MODEL_PRIORITY", " ")
    monkeypatch.setenv("MODEL_BASE_URL", "http://model.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "secret")
    resolution = await resolve_runtime()
    assert not resolution.ok
    assert resolution.error.code == "CONFIG_ERROR"


@pytest.mark.asyncio
async def test_config_profile_validation_and_duplicate_rejection(monkeypatch):
    monkeypatch.setenv("MODEL_PRIORITY", "good")
    monkeypatch.setenv("MODEL_BASE_URL", "http://model.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "secret")
    monkeypatch.setenv(
        "MODEL_PROFILE_JSON",
        json.dumps({"models": {"good": {"base_url": "ftp://bad", "auth_ref": "bad ref"}}}),
    )
    resolution = await resolve_runtime()
    assert not resolution.ok
    assert resolution.error.code == "PROFILE_ERROR"

    monkeypatch.setenv(
        "MODEL_PROFILE_JSON",
        '{"models":{"good":{"base_url":"http://good.test/v1","auth_ref":"FAKE_MODEL_KEY"},"good":{"base_url":"http://other.test/v1","auth_ref":"FAKE_MODEL_KEY"}}}',
    )
    resolution = await resolve_runtime()
    assert not resolution.ok
    assert resolution.error.code == "PROFILE_ERROR"


@pytest.mark.asyncio
async def test_config_missing_profile_and_invalid_auth_ref_are_structured(monkeypatch):
    monkeypatch.setenv("MODEL_PRIORITY", "missing")
    resolution = await resolve_runtime()
    assert not resolution.ok
    assert resolution.error.code == "CONFIG_ERROR"

    monkeypatch.setenv("MODEL_PRIORITY", "good")
    monkeypatch.setenv("MODEL_BASE_URL", "http://model.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "bad auth")
    resolution = await resolve_runtime()
    assert not resolution.ok
    assert resolution.error.code == "AUTH_CONFIG_ERROR"


@pytest.mark.asyncio
async def test_config_fallback_missing_profile_is_profile_error(monkeypatch):
    monkeypatch.setenv("MODEL_PRIORITY", "good")
    monkeypatch.setenv("MODEL_BASE_URL", "http://main.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "secret")
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request)

    monkeypatch.setenv("MODEL_FALLBACKS", "absent")
    monkeypatch.setattr(
        "pi_meta.model_runtime.httpx.AsyncClient",
        mock_async_client(handler),
    )
    resolution = await resolve_runtime()
    assert resolution.ok
    assert resolution.runtime.runtime.model == "good"
    assert resolution.runtime.probe_error_code is None


@pytest.mark.asyncio
async def test_override_allowlist_and_no_secret_in_runtime(monkeypatch):
    monkeypatch.setenv("MODEL_PRIORITY", "qwen3.8-27b")
    monkeypatch.setenv("MODEL_BASE_URL", "http://main.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request)

    monkeypatch.setenv("FAKE_MODEL_KEY", "secret-value")
    monkeypatch.setattr(
        "pi_meta.model_runtime.httpx.AsyncClient",
        mock_async_client(handler),
    )
    resolution = await resolve_runtime({"model": "qwen3.8-27b", "auth_ref": "FAKE_MODEL_KEY"})
    assert resolution.ok
    assert resolution.runtime.runtime.auth_ref == "FAKE_MODEL_KEY"
    assert "secret-value" not in repr(resolution)

    for override in (
        {"model": "qwen3.8-27b", "base_url": "http://evil.test/v1"},
        {"model": "qwen3.8-27b", "auth_header": "Bearer secret"},
        {"model": "qwen3.8-27b", "api_key": "secret"},
        {"model": "qwen3.8-27b", "auth_ref": "FAKE_MODEL_KEY", "extra": 1},
    ):
        with pytest.raises(ValueError):
            await resolve_runtime(override)


@pytest.mark.asyncio
async def test_health_path_does_not_duplicate_v1_base_suffix(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200,
            request=request,
            json={"data": [{"id": "test-model"}]},
        )

    monkeypatch.setenv("MODEL_PRIORITY", "good")
    monkeypatch.setenv("MODEL_BASE_URL", "http://good.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "secret")
    monkeypatch.setenv("MODEL_HEALTH_PATH", "/v1/models")
    monkeypatch.setattr(
        "pi_meta.model_runtime.httpx.AsyncClient",
        mock_async_client(handler),
    )

    resolution = await resolve_runtime()

    assert resolution.ok
    # base_url 已含 /v1,health_path 也以 /v1 开头 → 去重后只保留一个 /v1(来自 base)
    assert [request.url.path for request in calls] == ["/v1/models"]


@pytest.mark.asyncio
async def test_health_fallback_and_chat_retry_use_candidate_queue(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        path = request.url.path
        host = str(request.url.host)
        if path.endswith("/models"):
            if host != "second.test":
                return httpx.Response(503, request=request)
            return httpx.Response(200, json={"data": [{"id": "second"}]}, request=request)
        if path.endswith("/chat/completions"):
            if len([c for c in calls if c.url.path == "/chat/completions"]) == 1:
                return httpx.Response(429, request=request)
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok", "tool_calls": []}}]},
                request=request,
            )
        return httpx.Response(404, request=request)

    monkeypatch.setenv("MODEL_PRIORITY", "first,second")
    monkeypatch.setenv("MODEL_BASE_URL", "http://first.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "health-secret")
    monkeypatch.setenv("MODEL_PROFILE_JSON", json.dumps({
        "models": {
            "first": {"base_url": "http://first.test/v1", "auth_ref": "FAKE_MODEL_KEY"},
            "second": {"base_url": "http://second.test/v1", "auth_ref": "FAKE_MODEL_KEY"},
        }
    }))
    monkeypatch.setattr(
        "pi_meta.model_runtime.httpx.AsyncClient",
        mock_async_client(handler),
    )

    resolution = await resolve_runtime()
    assert resolution.ok
    assert resolution.runtime.runtime.model == "second"
    assert resolution.runtime.selected_index == 1
    assert resolution.runtime.available_indices == [1]
    assert resolution.runtime.degraded_from == "first"
    assert resolution.runtime.degraded_chain == ["first", "second"]

    result = await RuntimeClient.chat(resolution.runtime, {"messages": []})
    assert result.ok
    assert result.content == "ok"
    assert result.runtime_id == resolution.runtime.runtime_id
    assert result.degraded_chain == ["first", "second"]
    assert any("second.test" in str(c.url) for c in calls)


@pytest.mark.asyncio
async def test_health_fatal_auth_and_not_found_do_not_fallback(monkeypatch):
    for status, code in ((401, "AUTH_ERROR"), (404, "NOT_FOUND")):
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(status, request=request)

        monkeypatch.setenv("MODEL_PRIORITY", "first,second")
        monkeypatch.setenv("MODEL_BASE_URL", "http://first.test/v1")
        monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
        monkeypatch.setenv("FAKE_MODEL_KEY", "secret")
        monkeypatch.setattr(
            "pi_meta.model_runtime.httpx.AsyncClient",
            mock_async_client(handler),
        )
        resolution = await resolve_runtime()
        assert not resolution.ok
        assert resolution.error.code == code
        assert resolution.runtime is None
    assert calls == 1


@pytest.mark.asyncio
async def test_chat_parse_failure_is_not_downgraded(monkeypatch):
    health_calls = 0
    chat_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal health_calls, chat_calls
        if request.url.path.endswith("/models"):
            health_calls += 1
            return httpx.Response(200, request=request)
        chat_calls += 1
        if chat_calls == 1:
            return httpx.Response(200, text="not json", request=request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "fallback"}}]}, request=request)

    monkeypatch.setenv("MODEL_PRIORITY", "first,second")
    monkeypatch.setenv("MODEL_BASE_URL", "http://first.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "secret")
    monkeypatch.setattr(
        "pi_meta.model_runtime.httpx.AsyncClient",
        mock_async_client(handler),
    )
    resolution = await resolve_runtime()
    result = await RuntimeClient.chat(resolution.runtime, {"messages": []})
    assert not result.ok
    assert result.error.code == "PARSE_ERROR"
    assert result.degraded_chain == ["first", "second"]
    assert chat_calls == 1


@pytest.mark.asyncio
async def test_all_runtime_failures_return_no_runtime(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/models"):
            return httpx.Response(503, request=request)
        return httpx.Response(503, request=request)

    monkeypatch.setenv("MODEL_PRIORITY", "first")
    monkeypatch.setenv("MODEL_BASE_URL", "http://first.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "secret")
    monkeypatch.setattr(
        "pi_meta.model_runtime.httpx.AsyncClient",
        mock_async_client(handler),
    )
    resolution = await resolve_runtime()
    assert not resolution.ok
    assert resolution.error.code == "NO_RUNTIME"
    assert resolution.runtime is None


@pytest.mark.asyncio
async def test_dataclass_contracts_have_exact_required_fields():
    expected = {
        ModelRuntime: {"model", "base_url", "auth_ref", "timeout", "read_timeout", "health_path", "config_version"},
        ResolvedRuntime: {"runtime", "candidate_runtimes", "available_indices", "selected_index", "degraded_from", "degraded_chain", "runtime_id", "health_checked_at", "probe_status", "probe_error_code"},
        RuntimeResolution: {"ok", "runtime", "error"},
        ModelRuntimeError: {"code", "stage", "model", "redacted_message"},
        ChatResult: {"ok", "content", "tool_calls", "runtime_id", "degraded_chain", "error"},
        DispatchResult: {"ok", "agent", "raw", "case_snapshot", "findings", "runtime_id", "error"},
        AgentResult: {"ok", "findings", "trajectory", "case_snapshot", "error"},
        PlanResult: {"ok", "modules", "stop", "reason", "error"},
        ExtractionResult: {"ok", "findings", "runtime_id", "error"},
    }
    for cls, names in expected.items():
        assert is_dataclass(cls)
        actual = {f.name for f in fields(cls)}
        assert actual == names, (cls.__name__, actual)


@pytest.mark.asyncio
async def test_sessions_migrates_runtime_columns_and_redacts_metadata(monkeypatch, tmp_path):
    import pi_meta.sessions as sessions

    monkeypatch.setattr(sessions, "DB_PATH", str(tmp_path / "pimeta.db"))
    monkeypatch.setattr(sessions, "DATA_DIR", str(tmp_path))
    sessions._connect().close()
    sessions.save_task_metadata(
        "task-1", "target", "dvwa", "qwen3.8-27b", ["RedBee"], ["sqli"],
        "running", runtime_model="qwen3.8-27b", runtime_id="runtime-id",
        degraded_from="first", degraded_chain='["first"]', model_override='{"model":"qwen3.8-27b"}',
        runtime_error_code="NONE", runtime_error_summary="",
    )
    row = sessions.get_task_metadata("task-1")
    assert row["runtime_model"] == "qwen3.8-27b"
    assert row["runtime_id"] == "runtime-id"
    assert row["degraded_from"] == "first"
    assert row["model_override"] == '{"model":"qwen3.8-27b"}'
    assert "secret" not in json.dumps(row)


@pytest.mark.asyncio
async def test_all_5xx_health_statuses_fallback_to_next_candidate(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path.endswith("/models"):
            if str(request.url.host) != "second.test":
                return httpx.Response(599, request=request)
            return httpx.Response(200, json={"data": [{"id": "second"}]}, request=request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]}, request=request)

    monkeypatch.setenv("MODEL_PRIORITY", "first,second")
    monkeypatch.setenv("MODEL_BASE_URL", "http://first.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "health-secret")
    monkeypatch.setenv("MODEL_PROFILE_JSON", json.dumps({
        "models": {
            "first": {"base_url": "http://first.test/v1", "auth_ref": "FAKE_MODEL_KEY"},
            "second": {"base_url": "http://second.test/v1", "auth_ref": "FAKE_MODEL_KEY"},
        }
    }))
    monkeypatch.setattr("pi_meta.model_runtime.httpx.AsyncClient", mock_async_client(handler))
    resolution = await resolve_runtime()
    assert resolution.ok
    assert resolution.runtime.runtime.model == "second"
    assert resolution.runtime.degraded_from == "first"


@pytest.mark.asyncio
async def test_chat_rejects_model_runtime_snapshot_argument(monkeypatch):
    from pi_meta.model_runtime import ModelRuntime

    monkeypatch.setenv("MODEL_PRIORITY", "qwen3.8-27b")
    monkeypatch.setenv("MODEL_BASE_URL", "http://main.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "secret")
    result = await RuntimeClient.chat(runtime(), {"messages": []})
    assert not result.ok
    assert result.error.code == "TYPE_ERROR"


@pytest.mark.asyncio
async def test_runtime_id_is_stable_and_does_not_contain_auth_value(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request)

    monkeypatch.setenv("MODEL_PRIORITY", "qwen3.8-27b")
    monkeypatch.setenv("MODEL_BASE_URL", "http://main.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "rotated-secret")
    monkeypatch.setenv("MODEL_CONFIG_VERSION", "v2")
    monkeypatch.setattr("pi_meta.model_runtime.httpx.AsyncClient", mock_async_client(handler))
    first = await resolve_runtime()
    monkeypatch.setenv("FAKE_MODEL_KEY", "new-secret")
    second = await resolve_runtime()
    assert first.ok and second.ok
    assert first.runtime.runtime_id == second.runtime.runtime_id
    assert "rotated-secret" not in first.runtime.runtime_id
    assert "new-secret" not in first.runtime.runtime_id


@pytest.mark.asyncio
async def test_missing_main_auth_ref_returns_auth_config_error(monkeypatch):
    monkeypatch.setenv("MODEL_PRIORITY", "good")
    monkeypatch.setenv("MODEL_BASE_URL", "http://main.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "MISSING_KEY")
    resolution = await resolve_runtime()
    assert not resolution.ok
    assert resolution.error.code == "AUTH_CONFIG_ERROR"


def test_task_ids_do_not_reuse_sequence_after_restart(monkeypatch):
    import pi_meta.app as app_module

    class FakeUUID:
        def __init__(self, hex_value):
            self.hex = hex_value

    monkeypatch.setattr(
        app_module.uuid,
        "uuid4",
        lambda: FakeUUID("0123456789abcdef"),
    )
    first = app_module._new_task_id()

    monkeypatch.setattr(
        app_module.uuid,
        "uuid4",
        lambda: FakeUUID("fedcba9876543210"),
    )
    second = app_module._new_task_id()

    assert first == "t0123456789abcdef"
    assert second == "tfedcba9876543210"
    assert first != second


@pytest.mark.asyncio
async def test_config_module_priority_includes_deduplicated_fallback(monkeypatch):
    monkeypatch.setenv("MODEL_PRIORITY", "first,first,second")
    monkeypatch.setenv("MODEL_FALLBACKS", "second,third,third")
    monkeypatch.setenv("MODEL_BASE_URL", "http://main.test/v1")
    monkeypatch.setenv("MODEL_AUTH_REF", "FAKE_MODEL_KEY")
    monkeypatch.setenv("FAKE_MODEL_KEY", "secret")
    assert config.model_priority() == ["first", "second", "third"]
    assert config.MODEL_PRIORITY == config.model_priority()
