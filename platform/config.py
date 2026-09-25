"""统一配置:密钥从环境变量读取(外移,不硬编码进代码)。

运行时从 .env 或环境变量加载,缺少则给出清晰报错。
"""
from __future__ import annotations

import json
import os
import re
from urllib.parse import urlparse


_ENV_PATH = os.path.join(os.path.dirname(__file__), ".env")
_MODEL_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_AUTH_REF_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _load_dotenv(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


_load_dotenv(_ENV_PATH)


class ConfigError(RuntimeError):
    def __init__(self, code: str, message: str, detail: str = ""):
        self.code = code
        self.message = message
        self.detail = detail
        super().__init__(message)


class AuthConfigError(ConfigError):
    def __init__(self, message: str):
        super().__init__("AUTH_CONFIG_ERROR", message)


def _normalize_queue(raw: str, default: str = "") -> list[str]:
    values = [item.strip() for item in (raw or default).split(",") if item.strip()]
    return list(dict.fromkeys(values))


def _env_or_legacy(name: str, legacy_names: tuple[str, ...], default: str = "") -> str:
    for candidate in (name, *legacy_names):
        if os.environ.get(candidate):
            return os.environ[candidate]
    return default


def reload_env(path: str = _ENV_PATH) -> None:
    """重读 .env 并覆盖 os.environ(配置以 .env 为准, 改了立即生效, 无需重启进程)。

    ⚠️ 必须用覆盖赋值而不是 setdefault:setdefault 对"进程启动时已存在的键"
    不生效, .env 改旧值会被吞(2026-09-24 实证 bug)。
    """
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ[k.strip()] = v.strip()


def env(key: str, default: str = "") -> str:
    """实时读配置项(每次重读 .env → 改 .env 不用重启任何进程)。"""
    reload_env()
    return os.environ.get(key, default)


def _model_priority_from_env() -> list[str]:
    raw = env("MODEL_PRIORITY", _env_or_legacy("PMLABS_MODEL", ("MODEL_PRIORITY",), ""))
    queue = _normalize_queue(raw)
    for model in queue:
        if not _MODEL_RE.fullmatch(model):
            raise ConfigError("CONFIG_ERROR", "invalid model name in MODEL_PRIORITY", model)
    return queue


def model_priority() -> list[str]:
    queue = _model_priority_from_env()
    fallback = _normalize_queue(env("MODEL_FALLBACKS"))
    for model in [*queue, *fallback]:
        if not _MODEL_RE.fullmatch(model):
            raise ConfigError("CONFIG_ERROR", "invalid model name", model)
    fallback = [model for model in fallback if model not in queue]
    effective = list(dict.fromkeys([*queue, *fallback]))
    globals()["MODEL_PRIORITY"] = effective
    globals()["MODEL_FALLBACKS"] = fallback
    return effective


def _positive_float(name: str, value: str, default: float) -> float:
    try:
        parsed = float(value or default)
    except (TypeError, ValueError) as exc:
        raise ConfigError("CONFIG_ERROR", f"invalid {name}", name) from exc
    if parsed <= 0:
        raise ConfigError("CONFIG_ERROR", f"invalid {name}", name)
    return parsed


def model_runtime_config() -> dict:
    """Validate and normalize the unified model runtime configuration.

    This function owns configuration validation.  It returns runtime
    descriptors without resolving or exposing environment values.
    """
    priority = _model_priority_from_env()
    fallback = _normalize_queue(env("MODEL_FALLBACKS"))
    fallback = [model for model in fallback if model not in priority]
    profiles = _profile_documents(env("MODEL_PROFILE_JSON", ""))
    base_url = _env_or_legacy("MODEL_BASE_URL", ("PMLABS_BASE_URL", "OPEN_AI_SERVER_URL"))
    auth_ref = env("MODEL_AUTH_REF", "") or (
        "PMLABS_API_KEY" if os.environ.get("PMLABS_API_KEY") else
        ("OPEN_AI_KEY" if os.environ.get("OPEN_AI_KEY") else "")
    )
    config_version = env("MODEL_CONFIG_VERSION", "1")
    health_path = env("MODEL_HEALTH_PATH", "/v1/models")
    timeout = _positive_float("MODEL_TIMEOUT", env("MODEL_TIMEOUT", ""), 120.0)
    read_timeout = _positive_float("MODEL_READ_TIMEOUT", env("MODEL_READ_TIMEOUT", ""), 30.0)
    if not priority:
        raise ConfigError("CONFIG_ERROR", "MODEL_PRIORITY is empty", "")
    if not base_url or urlparse(base_url).scheme not in {"http", "https"} or not urlparse(base_url).netloc:
        raise ConfigError("CONFIG_ERROR", "MODEL_BASE_URL is required", "")
    if not auth_ref or not _AUTH_REF_RE.fullmatch(auth_ref):
        raise AuthConfigError("MODEL_AUTH_REF is missing or invalid")
    if not health_path.startswith("/"):
        raise ConfigError("CONFIG_ERROR", "MODEL_HEALTH_PATH must start with /", health_path)
    if not config_version:
        raise ConfigError("CONFIG_ERROR", "MODEL_CONFIG_VERSION is required", "")

    runtimes = []
    profile_errors = []
    for model in [*priority, *fallback]:
        profile = profiles.get(model)
        if profile:
            runtimes.append({
                "model": model,
                "base_url": profile["base_url"],
                "auth_ref": profile["auth_ref"],
                "timeout": timeout,
                "read_timeout": read_timeout,
                "health_path": health_path,
                "config_version": config_version,
            })
        elif base_url and auth_ref:
            runtimes.append({
                "model": model,
                "base_url": base_url,
                "auth_ref": auth_ref,
                "timeout": timeout,
                "read_timeout": read_timeout,
                "health_path": health_path,
                "config_version": config_version,
            })
        elif model in priority:
            raise ConfigError("CONFIG_ERROR", "selected model has no runtime configuration", model)
        else:
            profile_errors.append({
                "model": model,
                "code": "PROFILE_ERROR",
                "stage": "config",
                "message": "fallback model has no profile or main runtime",
            })
    return {
        "priority": priority,
        "fallbacks": fallback,
        "runtimes": runtimes,
        "profile_errors": profile_errors,
        "config_version": config_version,
    }


def _profile_documents(raw: str) -> dict:
    if not raw:
        return {}
    try:
        document = json.loads(raw, object_pairs_hook=_duplicate_key_hook)
    except ConfigError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise ConfigError("PROFILE_ERROR", "invalid MODEL_PROFILE_JSON") from exc
    models = document.get("models") if isinstance(document, dict) else None
    if not isinstance(models, dict):
        raise ConfigError("PROFILE_ERROR", "MODEL_PROFILE_JSON must contain a models object")
    result: dict[str, dict[str, str]] = {}
    for model, value in models.items():
        if not isinstance(model, str) or not _MODEL_RE.fullmatch(model):
            raise ConfigError("PROFILE_ERROR", "invalid model name in MODEL_PROFILE_JSON", model)
        if model in result:
            raise ConfigError("PROFILE_ERROR", "duplicate model profile", model)
        if not isinstance(value, dict):
            raise ConfigError("PROFILE_ERROR", "invalid model profile", model)
        base_url = value.get("base_url")
        auth_ref = value.get("auth_ref")
        parsed_url = urlparse(base_url) if isinstance(base_url, str) else None
        if (
            not isinstance(base_url, str)
            or parsed_url is None
            or parsed_url.scheme not in {"http", "https"}
            or not parsed_url.netloc
        ):
            raise ConfigError("PROFILE_ERROR", "invalid profile base_url", model)
        if not isinstance(auth_ref, str) or not _AUTH_REF_RE.fullmatch(auth_ref):
            raise ConfigError("PROFILE_ERROR", "invalid profile auth_ref", model)
        result[model] = {"base_url": base_url, "auth_ref": auth_ref}
    return result


def _duplicate_key_hook(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("PROFILE_ERROR", "duplicate model profile", key)
        result[key] = value
    return result


def resolve_auth_value(auth_ref: str) -> str:
    if not isinstance(auth_ref, str) or not _AUTH_REF_RE.fullmatch(auth_ref):
        raise AuthConfigError("invalid auth_ref")
    value = os.environ.get(auth_ref, "")
    if not value:
        raise AuthConfigError(f"auth ref {auth_ref} has no value")
    return value


def validate_trusted_override(explicit: object) -> dict[str, str] | None:
    if explicit is None:
        return None
    if isinstance(explicit, str):
        if not _MODEL_RE.fullmatch(explicit):
            raise ValueError("invalid model override")
        return {"model": explicit}
    if not isinstance(explicit, dict):
        raise ValueError("invalid model override")
    allowed = {"model", "auth_ref"}
    if not set(explicit).issubset(allowed) or not explicit:
        raise ValueError("invalid model override")
    model = explicit.get("model")
    if not isinstance(model, str) or not _MODEL_RE.fullmatch(model):
        raise ValueError("invalid model override")
    result = {"model": model}
    if "auth_ref" in explicit:
        auth_ref = explicit["auth_ref"]
        if not isinstance(auth_ref, str) or not _AUTH_REF_RE.fullmatch(auth_ref):
            raise ValueError("invalid auth_ref override")
        result["auth_ref"] = auth_ref
    return result


# ---- web auth (optional) ----
# PIMETA_WEB_TOKEN 非空则 Web 前端所有写操作需登录（POST /api/login 换 session token）；
# 为空(默认)则内网/演示模式不鉴权。
WEB_TOKEN = os.environ.get("PIMETA_WEB_TOKEN", "")

# ---- embedding ----
EMBED_URL = os.environ.get("EMBEDDING_URL", "")
EMBED_KEY = os.environ.get("EMBEDDING_KEY", "")
EMBED_MODEL = os.environ.get("EMBEDDING_MODEL", "bge-large-zh-v1.5")

# ---- RED-KB ----
REDKB_URL = os.environ.get("REDKB_URL", "http://127.0.0.1:8001")

# ---- 数据目录（可移植默认 <项目根>/data；PIMETA_DATA_DIR 改目录，PIMETA_DB 改整路径）----
DATA_DIR = os.environ.get(
    "PIMETA_DATA_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data"),
)
PIMETA_DB_PATH = os.environ.get("PIMETA_DB", os.path.join(DATA_DIR, "pimeta.db"))

# ---- PentAGI（可选，未配置时相关回流自动跳过）----
PENTAGI_URL = os.environ.get("PENTAGI_URL", "")
PENTAGI_TOKEN = os.environ.get("PENTAGI_TOKEN", "")
PENTAGI_PROVIDER = os.environ.get("PENTAGI_PROVIDER", "")

# ---- normalized model runtime ----
# Keep module aliases in sync with model_priority() for legacy callers.
# Validation is intentionally deferred until runtime resolution so imports remain
# usable in configuration bootstrap code.
_MODEL_PRIORITY_RAW = _model_priority_from_env()
_MODEL_FALLBACKS_RAW = _normalize_queue(env("MODEL_FALLBACKS"))
_MODEL_FALLBACKS_EFFECTIVE = [model for model in _MODEL_FALLBACKS_RAW if model not in _MODEL_PRIORITY_RAW]
MODEL_PRIORITY = list(dict.fromkeys([*_MODEL_PRIORITY_RAW, *_MODEL_FALLBACKS_EFFECTIVE]))
MODEL_FALLBACKS = _MODEL_FALLBACKS_EFFECTIVE
MODEL_BASE_URL = _env_or_legacy("MODEL_BASE_URL", ("PMLABS_BASE_URL", "OPEN_AI_SERVER_URL"))
_MODEL_AUTH_REF = env("MODEL_AUTH_REF", "") or (
    "PMLABS_API_KEY" if os.environ.get("PMLABS_API_KEY") else
    ("OPEN_AI_KEY" if os.environ.get("OPEN_AI_KEY") else "")
)
MODEL_AUTH_REF = _MODEL_AUTH_REF
MODEL_TIMEOUT = env("MODEL_TIMEOUT", "120")
MODEL_READ_TIMEOUT = env("MODEL_READ_TIMEOUT", "30")
MODEL_HEALTH_PATH = env("MODEL_HEALTH_PATH", "/v1/models")
MODEL_CONFIG_VERSION = env("MODEL_CONFIG_VERSION", "1")
MODEL_PROFILE_JSON = env("MODEL_PROFILE_JSON", "")


def require(key: str) -> str:
    v = env(key, "")
    if not v:
        raise RuntimeError(f"缺少环境变量 {key} —— 请在 platform/.env 或环境变量中配置")
    return v
