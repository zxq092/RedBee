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
    monkeypatch.setattr(config, "_load_dotenv", lambda path=None: None)
    monkeypatch.setattr(config, "env", lambda key, default="": os.environ.get(key, default))
    yield
