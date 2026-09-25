from __future__ import annotations

import pytest

import agents.orchestrator_v2 as orch_module
from agents.orchestrator_v2 import _run_child


@pytest.mark.asyncio
async def test_run_child_tool_call_does_not_access_outer_self(monkeypatch):
    class State:
        def __init__(self):
            self.turn = 0
            self.tool_calls = 0

    class FakeChild:
        def __init__(self, runtime=None):
            self.state = State()
            self.messages = [{"role": "system"}, {"role": "user"}]
            self.container = None

        def _build_initial_messages(self, *args, **kwargs):
            pass

        async def _docker_run(self, *args, **kwargs):
            self.container = "test-container"

        def _compact_messages(self):
            pass

        def _inject_budget_notice(self):
            pass

        async def _chat(self, messages, runtime):
            if self.state.turn == 0:
                return {
                    "tool_calls": [{
                        "id": "call-1",
                        "type": "function",
                        "function": {"name": "http_request", "arguments": "{}"},
                    }]
                }
            return {"tool_calls": None, "content": "done"}

        async def _exec_tool_calls(self, calls, task_id, target, progress_cb=None):
            self.state.tool_calls += 1

        async def _cleanup(self):
            pass

    calls = []
    child = FakeChild()
    monkeypatch.setattr(orch_module.InhouseAgent, "__init__", FakeChild.__init__)
    monkeypatch.setattr(orch_module.InhouseAgent, "_build_initial_messages", lambda self, *args, **kwargs: None)
    monkeypatch.setattr(orch_module.InhouseAgent, "_compact_messages", lambda self: None)
    monkeypatch.setattr(orch_module.InhouseAgent, "_inject_budget_notice", lambda self: None)
    monkeypatch.setattr(orch_module.InhouseAgent, "_drain_notes", lambda self: None)
    monkeypatch.setattr(orch_module.InhouseAgent, "_chat", FakeChild._chat)
    monkeypatch.setattr(orch_module.InhouseAgent, "_docker_run", FakeChild._docker_run)
    monkeypatch.setattr(orch_module.InhouseAgent, "_exec_tool_calls", FakeChild._exec_tool_calls)
    monkeypatch.setattr(orch_module.InhouseAgent, "_cleanup", FakeChild._cleanup)
    runtime = type("Runtime", (), {"model": "model"})

    async def invoke():
        return await _run_child(
            module="sqli",
            target="http://target.test",
            task="test",
            task_id="task-1",
            intel_block="",
            runtime=runtime,
            progress_cb=calls.append,
        )

    result = await invoke()
    assert result.module == "sqli"
    assert calls
