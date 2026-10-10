import os

import pytest
import config

_ENV_KEYS = [
    "MODEL_PRIORITY", "MODEL_FALLBACKS", "MODEL_BASE_URL", "MODEL_AUTH_REF",
    "MODEL_TIMEOUT", "MODEL_READ_TIMEOUT", "MODEL_HEALTH_PATH",
    "MODEL_CONFIG_VERSION", "MODEL_PROFILE_JSON",
    "PMLABS_MODEL", "PMLABS_BASE_URL", "PMLABS_API_KEY",
    "OPEN_AI_SERVER_URL", "OPEN_AI_KEY",
]


@pytest.fixture(autouse=True)
def _isolate_model_env(monkeypatch):
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    # LLM 原始字节录制目录隔离：RuntimeClient.chat 每次调用都落盘，
    # 不隔离会把测试记录（first/second.test）写进生产 data/llm_records
    monkeypatch.setattr(config, "_load_dotenv", lambda path=None: None)
    monkeypatch.setattr(config, "env", lambda key, default="": os.environ.get(key, default))
    yield


@pytest.fixture(autouse=True)
def _isolate_llm_records(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_RECORD_DIR", str(tmp_path / "llm_records_test"))
    yield


@pytest.fixture(autouse=True)
def _isolate_pimeta_db(tmp_path, monkeypatch):
    """pi_meta 的 DB（sessions/board/llm_breakers 等）重定向到 per-test 临时库，
    防熔断器/漏洞板写入污染生产 data/pimeta.db。"""
    import pi_meta.sessions as sessions
    import pi_meta.board as board

    db = str(tmp_path / "pimeta_test.db")
    monkeypatch.setattr(sessions, "DB_PATH", db)
    # 走生产惰性建表路径把基线表（sessions+findings）建出来：直接读 findings 的
    # 测试（如 orchestrator._collect_findings）对着全新临时库不会 "no such table"
    conn = board._conn()
    conn.close()
    yield


@pytest.fixture(autouse=True)
def _isolate_agents_db(tmp_path, monkeypatch):
    """agents 层的 DB（tools 表 + intercept_rules/intercept_decisions）同样隔离。
    executor 每个工具调用都过 intercept_check，不隔离会把种子规则/审计写进生产库。
    ⚠️ 与 sessions 用同一个临时文件——生产里两者本就指向同一个 pimeta.db。"""
    import agents.tools as tools_mod

    monkeypatch.setattr(tools_mod, "DB_PATH", str(tmp_path / "pimeta_test.db"))
    # tools 的 schema（coverage/agent_memory/todos/notes）在 import 时已对生产库建过，
    # 切到临时库后必须重建，否则 orchestrator 直读 coverage 报 no such table
    tools_mod._ensure_schema()
    yield
