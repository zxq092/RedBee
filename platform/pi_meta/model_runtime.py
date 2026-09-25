from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from config import (
    AuthConfigError,
    ConfigError,
    model_runtime_config as config_model_runtime_config,
    resolve_auth_value,
    validate_trusted_override,
    env as _cfg_env,
)

_MODEL_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_AUTH_REF_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_TRANSIENT_STATUS = {429, *range(500, 600)}
_MAX_CHAT_RETRIES = 2


@dataclass(frozen=True)
class ModelRuntime:
    model: str
    base_url: str
    auth_ref: str
    timeout: float
    read_timeout: float
    health_path: str
    config_version: str


@dataclass(frozen=True)
class ResolvedRuntime:
    runtime: ModelRuntime
    candidate_runtimes: List[ModelRuntime]
    available_indices: List[int]
    selected_index: int
    degraded_from: Optional[str]
    degraded_chain: List[str]
    runtime_id: str
    health_checked_at: str
    probe_status: str
    probe_error_code: Optional[str]


@dataclass(frozen=True)
class RuntimeResolution:
    ok: bool
    runtime: Optional[ResolvedRuntime]
    error: Optional[ModelRuntimeError]


@dataclass(frozen=True)
class ModelRuntimeError:
    code: str
    stage: str
    model: Optional[str]
    redacted_message: str


@dataclass(frozen=True)
class ChatResult:
    ok: bool
    content: str
    tool_calls: List[Dict[str, Any]]
    runtime_id: str
    degraded_chain: List[str]
    error: Optional[ModelRuntimeError]


@dataclass(frozen=True)
class AgentResult:
    ok: bool
    findings: List[Dict[str, Any]]
    trajectory: Dict[str, Any]
    case_snapshot: Optional[Dict[str, Any]]
    error: Optional[ModelRuntimeError]


@dataclass(frozen=True)
class DispatchResult:
    ok: bool
    agent: str
    raw: str
    case_snapshot: Optional[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    runtime_id: str
    error: Optional[ModelRuntimeError]


@dataclass(frozen=True)
class PlanResult:
    ok: bool
    modules: List[str]
    stop: bool
    reason: str
    error: Optional[ModelRuntimeError]


@dataclass(frozen=True)
class ExtractionResult:
    ok: bool
    findings: List[Dict[str, Any]]
    runtime_id: str
    error: Optional[ModelRuntimeError]


class RuntimeResolutionError(RuntimeError):
    def __init__(self, resolution: RuntimeResolution):
        self.resolution = resolution
        error = resolution.error
        super().__init__(error.redacted_message if error else "runtime resolution failed")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _runtime_id(runtime: ModelRuntime) -> str:
    material = "|".join((runtime.config_version, runtime.model, runtime.base_url, runtime.auth_ref))
    return "rt-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _error(code: str, stage: str, model: Optional[str], message: str) -> ModelRuntimeError:
    return ModelRuntimeError(code=code, stage=stage, model=model, redacted_message=message)


def _base_url_with_path(base_url: str, health_path: str) -> str:
    return base_url.rstrip("/") + health_path


def _health_url(base_url: str, health_path: str) -> str:
    normalized_base = base_url.rstrip("/")
    if normalized_base.endswith("/v1") and health_path.startswith("/v1"):
        # base_url 已含 /v1,health_path 也以 /v1 开头 → 只保留 base 的 /v1 + health 去掉前缀
        return normalized_base + health_path[3:]
    return _base_url_with_path(base_url, health_path)


def coerce_resolved_runtime(runtime: ResolvedRuntime | ModelRuntime) -> ResolvedRuntime:
    if isinstance(runtime, ResolvedRuntime):
        return runtime
    if isinstance(runtime, ModelRuntime):
        return ResolvedRuntime(
            runtime=runtime,
            candidate_runtimes=[runtime],
            available_indices=[0],
            selected_index=0,
            degraded_from=None,
            degraded_chain=[runtime.model],
            runtime_id=_runtime_id(runtime),
            health_checked_at=_utcnow(),
            probe_status="unprobed",
            probe_error_code=None,
        )
    raise TypeError("runtime must be a ResolvedRuntime or ModelRuntime")


def _candidate_runtimes(explicit: Optional[Any]) -> tuple[List[ModelRuntime], Optional[ModelRuntimeError]]:
    override = validate_trusted_override(explicit)
    try:
        config = config_model_runtime_config()
    except ConfigError as exc:
        return [], _error(exc.code, "config", None, exc.message)
    priority = config["priority"]
    runtimes_by_model = {runtime["model"]: runtime for runtime in config["runtimes"]}
    if override:
        model = override["model"]
        if model not in runtimes_by_model:
            return [], _error("PROFILE_ERROR", "config", model, "override model is not configured")
        ordered_models = [model] + [item for item in priority if item != model]
    else:
        ordered_models = priority
    runtimes: List[ModelRuntime] = []
    for model in ordered_models:
        raw_runtime = runtimes_by_model.get(model)
        if raw_runtime is None:
            continue
        runtime = ModelRuntime(
            model=raw_runtime["model"],
            base_url=raw_runtime["base_url"],
            auth_ref=override.get("auth_ref", raw_runtime["auth_ref"]) if override else raw_runtime["auth_ref"],
            timeout=raw_runtime["timeout"],
            read_timeout=raw_runtime["read_timeout"],
            health_path=raw_runtime["health_path"],
            config_version=raw_runtime["config_version"],
        )
        runtimes.append(runtime)
    if not runtimes:
        return [], _error("CONFIG_ERROR", "config", None, "no configured runtime is available")
    return runtimes, None


class RuntimeResolver:
    def __init__(self, explicit: Optional[Any] = None, trusted: bool = True):
        self.explicit = explicit
        self.trusted = trusted

    async def resolve_runtime(self, explicit: Optional[Any] = None, *, trusted: Optional[bool] = None) -> RuntimeResolution:
        override = self.explicit if explicit is None else explicit
        if override and (trusted is False if trusted is not None else not self.trusted):
            raise ValueError("model override requires a trusted internal caller")
        candidates, config_error = _candidate_runtimes(override)
        if config_error:
            return RuntimeResolution(ok=False, runtime=None, error=config_error)
        available: List[int] = []
        degraded_from: Optional[str] = None
        degraded_chain: List[str] = []
        selected_index: Optional[int] = None
        selected_runtime: Optional[ModelRuntime] = None
        for index, candidate in enumerate(candidates):
            degraded_chain.append(candidate.model)
            probe_status, probe_error_code, probe_error = await self._probe(candidate)
            if probe_status == "healthy":
                available.append(index)
                if selected_index is None:
                    selected_index = index
                    selected_runtime = candidate
                continue
            if degraded_from is None:
                degraded_from = candidate.model
            if probe_error_code in {"AUTH_CONFIG_ERROR", "AUTH_ERROR", "NOT_FOUND"}:
                return RuntimeResolution(ok=False, runtime=None, error=probe_error)
        if selected_runtime is None:
            model = candidates[0].model if candidates else None
            return RuntimeResolution(
                ok=False,
                runtime=None,
                error=_error("NO_RUNTIME", "health", model, "all configured model runtimes are unavailable"),
            )
        resolved = ResolvedRuntime(
            runtime=selected_runtime,
            candidate_runtimes=candidates,
            available_indices=available,
            selected_index=selected_index or 0,
            degraded_from=degraded_from,
            degraded_chain=degraded_chain,
            runtime_id=_runtime_id(selected_runtime),
            health_checked_at=_utcnow(),
            probe_status="healthy",
            probe_error_code=None,
        )
        return RuntimeResolution(ok=True, runtime=resolved, error=None)

    @staticmethod
    async def _probe(runtime: ModelRuntime) -> tuple[str, Optional[str], Optional[ModelRuntimeError]]:
        url = _health_url(runtime.base_url, runtime.health_path)

        timeout = httpx.Timeout(runtime.timeout, connect=10.0, read=runtime.read_timeout)
        last_error: Optional[ModelRuntimeError] = None
        for attempt in range(2):
            try:
                auth_value = resolve_auth_value(runtime.auth_ref)
            except AuthConfigError as exc:
                return "fatal", "AUTH_CONFIG_ERROR", _error("AUTH_CONFIG_ERROR", "health", runtime.model, str(exc))
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.get(url, headers={"Authorization": f"Bearer {auth_value}"})
                    await response.aread()
                    if response.status_code == 200:
                        return "healthy", None, None
                    if response.status_code == 401:
                        return "fatal", "AUTH_ERROR", _error("AUTH_ERROR", "health", runtime.model, "health probe rejected authentication")
                    if response.status_code == 404:
                        return "fatal", "NOT_FOUND", _error("NOT_FOUND", "health", runtime.model, "health endpoint not found")
                    if response.status_code == 429 or 500 <= response.status_code < 600:
                        last_error = _error(
                            "RATE_LIMIT" if response.status_code == 429 else "SERVER_ERROR",
                            "health",
                            runtime.model,
                            f"health probe returned HTTP {response.status_code}",
                        )
                        if attempt == 1:
                            return "unhealthy", last_error.code, last_error
                        await asyncio.sleep(0.05)
                        continue
                    return "fatal", f"HTTP_{response.status_code}", _error(
                        f"HTTP_{response.status_code}", "health", runtime.model,
                        f"health probe returned HTTP {response.status_code}",
                    )
            except asyncio.TimeoutError:
                last_error = _error("TIMEOUT", "health", runtime.model, "health probe timed out")
                if attempt == 1:
                    return "unhealthy", "TIMEOUT", last_error
                await asyncio.sleep(0.05)
            except httpx.TransportError:
                last_error = _error("NETWORK_ERROR", "health", runtime.model, "health probe transport failure")
                if attempt == 1:
                    return "unhealthy", "NETWORK_ERROR", last_error
                await asyncio.sleep(0.05)
        return "unhealthy", last_error.code if last_error else "PROBE_ERROR", last_error or _error("PROBE_ERROR", "health", runtime.model, "health probe failed")


async def resolve_runtime(explicit: Optional[Any] = None, *, trusted: bool = True) -> RuntimeResolution:
    return await RuntimeResolver(explicit=explicit, trusted=trusted).resolve_runtime()


class _LLMConcurrencyGate:
    """全局 LLM 并发闸门：限制全平台(跨任务)在飞的 chat HTTP 请求数。

    限额每次 acquire 实时读 .env(PIMETA_GLOBAL_MAX_LLM_CONCURRENCY, 默认 4)，改 .env 立即生效。
    动机：多任务并行时并发大上下文请求压垮单一 vLLM 端点(2026-09-24 实测 8 路并发致
    18 个 child 中 7 个 720s 超时死亡)——每任务并行数治不了跨任务叠加，必须全局闸门。
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._in_flight = 0

    @staticmethod
    def _limit() -> int:
        try:
            return max(1, int(_cfg_env("PIMETA_GLOBAL_MAX_LLM_CONCURRENCY", "4")))
        except (TypeError, ValueError):
            return 4

    @property
    def in_flight(self) -> int:
        return self._in_flight

    async def __aenter__(self) -> "_LLMConcurrencyGate":
        while True:
            limit = self._limit()
            async with self._lock:
                if self._in_flight < limit:
                    self._in_flight += 1
                    return self
            await asyncio.sleep(0.5)

    async def __aexit__(self, *exc: Any) -> bool:
        async with self._lock:
            if self._in_flight > 0:
                self._in_flight -= 1
        return False


_llm_gate = _LLMConcurrencyGate()


class RuntimeClient:
    @staticmethod
    async def chat(resolved: ResolvedRuntime, payload: Dict[str, Any]) -> ChatResult:
        if not isinstance(resolved, ResolvedRuntime):
            return ChatResult(False, "", [], "", [], _error("TYPE_ERROR", "chat", None, "RuntimeClient.chat requires ResolvedRuntime"))
        candidates = [resolved.candidate_runtimes[index] for index in resolved.available_indices]
        if not candidates:
            return ChatResult(False, "", [], resolved.runtime_id, [], _error("NO_RUNTIME", "chat", None, "no available runtime"))
        payload = dict(payload)
        attempted: List[str] = []
        degraded_chain = list(resolved.degraded_chain)
        for candidate in candidates:
            attempted.append(candidate.model)
            last_error: Optional[ModelRuntimeError] = None
            for attempt in range(_MAX_CHAT_RETRIES + 1):
                try:
                    auth_value = resolve_auth_value(candidate.auth_ref)
                except AuthConfigError as exc:
                    return ChatResult(False, "", [], resolved.runtime_id, degraded_chain, _error("AUTH_CONFIG_ERROR", "chat", candidate.model, str(exc)))
                payload["model"] = candidate.model
                timeout = httpx.Timeout(candidate.timeout, connect=10.0, read=candidate.read_timeout)
                try:
                    async with _llm_gate:
                        async with httpx.AsyncClient(timeout=timeout) as client:
                            response = await client.post(
                                _base_url_with_path(candidate.base_url, "/chat/completions"),
                                json=payload,
                                headers={"Authorization": f"Bearer {auth_value}"},
                            )
                    if response.status_code == 200:
                        try:
                            document = response.json()
                            choices = document.get("choices")
                            message = choices[0].get("message") if isinstance(choices, list) and choices else None
                            content = message.get("content") if isinstance(message, dict) else ""
                            tool_calls = message.get("tool_calls") if isinstance(message, dict) else []
                            if not isinstance(tool_calls, list):
                                tool_calls = []
                            return ChatResult(True, str(content or ""), tool_calls, resolved.runtime_id, degraded_chain, None)
                        except (ValueError, AttributeError, TypeError) as exc:
                            return ChatResult(False, "", [], resolved.runtime_id, degraded_chain, _error("PARSE_ERROR", "parse", candidate.model, "invalid chat completion response"))
                    if response.status_code == 429 or 500 <= response.status_code < 600:
                        if attempt < _MAX_CHAT_RETRIES:
                            last_error = _error("RATE_LIMIT" if response.status_code == 429 else "SERVER_ERROR", "chat", candidate.model, f"chat returned HTTP {response.status_code}")
                            await asyncio.sleep(0.05 * (attempt + 1))
                            continue
                        last_error = _error("RATE_LIMIT" if response.status_code == 429 else "SERVER_ERROR", "chat", candidate.model, f"chat returned HTTP {response.status_code}")
                        break
                    if response.status_code == 401:
                        return ChatResult(False, "", [], resolved.runtime_id, degraded_chain, _error("AUTH_ERROR", "chat", candidate.model, "chat authentication rejected"))
                    if response.status_code == 404:
                        return ChatResult(False, "", [], resolved.runtime_id, degraded_chain, _error("NOT_FOUND", "chat", candidate.model, "chat endpoint not found"))
                    last_error = _error(f"HTTP_{response.status_code}", "chat", candidate.model, f"chat returned HTTP {response.status_code}")
                    break
                except (asyncio.TimeoutError, httpx.TimeoutException):
                    last_error = _error("TIMEOUT", "chat", candidate.model, "chat timed out")
                    if attempt < _MAX_CHAT_RETRIES:
                        await asyncio.sleep(0.05 * (attempt + 1))
                        continue
                    break
                except httpx.TransportError:
                    last_error = _error("NETWORK_ERROR", "chat", candidate.model, "chat transport failure")
                    if attempt < _MAX_CHAT_RETRIES:
                        await asyncio.sleep(0.05 * (attempt + 1))
                        continue
                    break
            degraded_chain.extend(model for model in [candidate.model] if model not in degraded_chain)
        return ChatResult(False, "", [], resolved.runtime_id, degraded_chain, _error("NO_RUNTIME", "chat", None, "all available model runtimes failed"))


__all__ = [
    "AgentResult",
    "ChatResult",
    "DispatchResult",
    "ExtractionResult",
    "ModelRuntime",
    "ModelRuntimeError",
    "PlanResult",
    "ResolvedRuntime",
    "RuntimeClient",
    "RuntimeResolution",
    "RuntimeResolver",
    "RuntimeResolutionError",
    "coerce_resolved_runtime",
    "resolve_runtime",
]
