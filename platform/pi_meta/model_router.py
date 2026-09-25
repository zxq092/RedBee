"""Model priority queue + automatic degradation (PI 层控制模型).

模型路由 + 自动降级：优先级队列来自 config/.env(MODEL_PRIORITY)，首选不可用就
降级到下一个可用模型，记录 degraded_from。这是「模型在 PI 层统一控制」的正解：
换模型 = 改 .env，代码只读取与调度，不 hardcode。
"""
from __future__ import annotations

from typing import Dict, List, Optional

from config import model_priority
from .model_runtime import ResolvedRuntime, RuntimeResolution, resolve_runtime


class ModelRouter:
    """持有用户配置的优先级队列，首选挂则降级到下一个可用模型。

    支持运行时 override：set_override(model) 把队列临时改为"只用该模型"（手动切换），
    clear_override() 恢复 .env 配置的队列。供 Web/UI 手动指定模型用（运行时改、不重启）。
    """

    def __init__(self, priority: Optional[List[str]] = None):
        self._base_priority = list(priority if priority is not None else model_priority())
        self.model_priority = list(self._base_priority)
        self._override: Optional[str] = None
        self._unavailable: set = set()

    @property
    def override(self) -> Optional[str]:
        return self._override

    def set_override(self, model: str) -> None:
        """运行时只使用指定模型（手动切换/指定，可逗号分隔多候选）。校验通过后生效。"""
        import re
        tokens = [m.strip() for m in (model or "").split(",") if m.strip()]
        if not tokens:
            raise ValueError("model override must be non-empty")
        for m in tokens:
            if not re.fullmatch(r"[A-Za-z0-9._-]+", m):
                raise ValueError(f"invalid model override: {m!r}")
        self._override = ",".join(tokens)
        self.model_priority = tokens

    def clear_override(self) -> None:
        """恢复 .env 配置的优先级队列。"""
        self._override = None
        self.model_priority = list(self._base_priority)

    def mark_unavailable(self, model: str) -> None:
        self._unavailable.add(model)

    def mark_available(self, model: str) -> None:
        self._unavailable.discard(model)

    async def resolve_runtime(
        self,
        explicit: Optional[object] = None,
        *,
        trusted: bool = False,
    ) -> RuntimeResolution:
        """Resolve the task runtime through the shared runtime contract."""
        return await resolve_runtime(explicit, trusted=trusted)

    async def resolve(self, explicit: Optional[object] = None) -> Dict[str, object]:
        """Compatibility model-name API; failures never expose a preferred model."""
        resolution = await self.resolve_runtime(explicit, trusted=True)
        if not resolution.ok or resolution.runtime is None:
            return {"model": None, "error": resolution.error}
        return {
            "model": resolution.runtime.runtime.model,
            "degraded_from": resolution.runtime.degraded_from,
        }
