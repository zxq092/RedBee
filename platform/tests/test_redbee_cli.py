from __future__ import annotations

import argparse
import json

import httpx
import pytest

import redbee_cli
from pi_meta import sessions


def test_parse_params_types():
    assert redbee_cli.parse_params(["max_modules=3", "skip_recon=true", "task_budget=90.5", "mode=ctf"]) == {
        "max_modules": 3,
        "skip_recon": True,
        "task_budget": 90.5,
        "mode": "ctf",
    }


def test_parse_params_rejects_invalid():
    with pytest.raises(SystemExit):
        redbee_cli.parse_params(["no-value"])


def test_build_task_body_marks_cli_source():
    body = redbee_cli.build_task_body(
        task="capture flag",
        target="http://127.0.0.1:8080",
        session_id="sess123",
        target_id="demo",
        agents=["RedBee"],
        params={"max_modules": 1},
        source="cli",
        operator="root",
    )
    assert body["source"] == "cli"
    assert body["operator"] == "root"
    assert body["params"] == {"max_modules": 1}
    assert body["session_id"] == "sess123"


def test_redbee_client_json_and_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/ok":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(400, json={"error": "bad"})

    client = redbee_cli.RedbeeClient("http://testserver", transport=httpx.MockTransport(handler))
    try:
        assert client.get("/ok") == {"ok": True}
        with pytest.raises(redbee_cli.ApiError):
            client.get("/bad")
    finally:
        client.close()


def test_redbee_client_sse_parsing():
    raw = b'data: {"type":"live","slots":{}}\n\ndata: {"type":"done","reason":"task_finished"}\n\n'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=raw, headers={"content-type": "text/event-stream"})

    client = redbee_cli.RedbeeClient("http://testserver", transport=httpx.MockTransport(handler))
    try:
        events = list(client.iter_sse("/api/task/t1/stream"))
    finally:
        client.close()
    assert [e["type"] for e in events] == ["live", "done"]
    assert events[1]["reason"] == "task_finished"


def test_cmd_task_run_posts_cli_source_and_operator(monkeypatch):
    calls = []

    class FakeClient:
        def post(self, path, payload=None):
            calls.append((path, payload or {}))
            if path == "/api/sessions":
                return {"id": "auto-session"}
            return {"task_id": "t123", "status": "dispatched", "mode": "ctf"}

        def close(self):
            pass

    args = argparse.Namespace(
        task="capture flag",
        target="http://target",
        session_id="",
        target_id="demo",
        agent=None,
        param=["max_modules=1"],
        operator="ci",
        json=False,
    )
    redbee_cli.cmd_task_run(args, FakeClient())
    assert calls[0][0] == "/api/sessions"
    assert calls[1][0] == "/api/task"
    body = calls[1][1]
    assert body["source"] == "cli"
    assert body["operator"] == "ci"
    assert body["session_id"] == "auto-session"
    assert body["params"] == {"max_modules": 1}


def test_task_metadata_source_survives_status_updates():
    sessions.save_task_metadata(
        "t-source", "http://target", "target-id", "", ["RedBee"], [], "running",
        session_id="s1", task_text="capture flag", mode="ctf", source="cli", operator="root")
    sessions.save_task_metadata(
        "t-source", "http://target", "target-id", "model-x", ["RedBee"], ["objective"], "done",
        session_id="s1")
    meta = sessions.get_task_metadata("t-source")
    assert meta["source"] == "cli"
    assert meta["operator"] == "root"
    assert meta["status"] == "done"
    tasks = sessions.list_tasks()
    row = next(t for t in tasks if t["task_id"] == "t-source")
    assert row["source"] == "cli"
    assert row["operator"] == "root"


def test_human_status_prints_source(capsys):
    data = {
        "task_id": "t1",
        "meta": {"source": "cli", "operator": "ci", "target": "http://x", "mode": "ctf"},
        "board": {"status": "done", "findings": [{"id": 1, "severity": "high", "status": "found", "title": "x"}]},
    }
    redbee_cli.human_status(data)
    out = capsys.readouterr().out
    assert "source: cli" in out
    assert "operator: ci" in out
    assert "findings: 1" in out
