"""⑥ LLM 原始字节录制测试（llm_recorder）。

覆盖：成功精简/失败全量落盘、超时 response_raw=None、绝不抛异常、
轮转只留 KEEP 个、索引倒序+limit、路径穿越防护、开关关闭、请求体截断。
"""
from __future__ import annotations

import json
import os

import pytest

from pi_meta import llm_recorder


@pytest.fixture(autouse=True)
def _records_dir(tmp_path, monkeypatch):
    d = str(tmp_path / "llm_records")
    monkeypatch.setenv("LLM_RECORD_DIR", d)
    return d


def _rec(model="m1", status=200, is_success=True, response_text="{}"):
    return llm_recorder.record_call(
        model=model, host="h.test", status=status, elapsed_ms=123.456,
        payload={"messages": [{"role": "user", "content": "hi"}]},
        response_text=response_text, result="ok" if is_success else f"HTTP_{status}",
        is_success=is_success,
    )


# ---- 落盘形态 ----

def test_success_record_is_concise(tmp_path):
    name = _rec()
    assert name and name.endswith(".json")
    data = json.load(open(os.path.join(str(tmp_path), "llm_records", name), encoding="utf-8"))
    assert data["model"] == "m1"
    assert data["status"] == 200
    assert data["result"] == "ok"
    assert data["n_messages"] == 1
    assert data["ctx_chars"] == 2
    assert data["response_head"] == "{}"
    assert "request" not in data  # 成功不留请求体（成本敏感）


def test_failure_record_keeps_request_and_raw_bytes(tmp_path):
    name = _rec(status=500, is_success=False, response_text="raw-bytes-here")
    data = json.load(open(os.path.join(str(tmp_path), "llm_records", name), encoding="utf-8"))
    assert data["status"] == 500
    assert data["result"] == "HTTP_500"
    assert json.loads(data["request"])["messages"][0]["content"] == "hi"
    assert data["response_raw"] == "raw-bytes-here"


def test_timeout_record_has_null_response(tmp_path):
    name = llm_recorder.record_call(
        model="m1", host="h.test", status=None, elapsed_ms=90400.0,
        payload={"messages": []}, response_text=None, result="TIMEOUT", is_success=False,
    )
    data = json.load(open(os.path.join(str(tmp_path), "llm_records", name), encoding="utf-8"))
    assert data["status"] is None
    assert data["result"] == "TIMEOUT"
    assert data["response_raw"] is None
    assert data["request"] == json.dumps({"messages": []}, ensure_ascii=False)


# ---- 健壮性：录制故障不得影响主链路 ----

def test_record_never_raises_on_bad_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_RECORD_DIR", str(tmp_path / ("a" * 300)))  # 路径超长 → makedirs 失败
    assert _rec() is None


def test_record_never_raises_when_dir_is_file(monkeypatch, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("LLM_RECORD_DIR", str(blocker / "sub"))  # makedirs 撞文件 → NotADirectoryError
    assert _rec() is None


def test_disabled_returns_none_and_writes_nothing(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_RECORD_ENABLED", "0")
    assert _rec() is None
    assert not os.path.exists(os.path.join(str(tmp_path), "llm_records"))


def test_request_body_capped(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_RECORD_REQ_CAP", "1500")  # 下限 1000，取 1500 验证截断生效
    big = "x" * 5000
    name = llm_recorder.record_call(
        model="m1", host="h.test", status=500, elapsed_ms=1.0,
        payload={"messages": [{"role": "user", "content": big}]},
        response_text=None, result="HTTP_500", is_success=False,
    )
    data = json.load(open(os.path.join(str(tmp_path), "llm_records", name), encoding="utf-8"))
    assert len(data["request"]) == 1500


# ---- 索引与列表 ----

def test_list_records_reverse_chronological_with_limit(tmp_path):
    for i in range(5):
        _rec(model=f"m{i}")
    out = llm_recorder.list_records(limit=3)
    assert len(out) == 3
    models = [r["model"] for r in out]
    assert models == ["m4", "m3", "m2"]  # 倒序
    for r in out:
        assert {"file", "ts", "model", "host", "status", "elapsed_ms", "result"} <= set(r)


def test_list_records_empty_dir():
    assert llm_recorder.list_records() == []


# ---- 详情与路径穿越 ----

def test_get_roundtrip_and_traversal_guard(tmp_path):
    name = _rec()
    data = llm_recorder.get_record(name)
    assert data is not None and data["model"] == "m1"
    assert llm_recorder.get_record("../pimeta.db") is None
    assert llm_recorder.get_record("a/b.json") is None
    assert llm_recorder.get_record("index.jsonl") is None  # 不在录制命名规则内
    assert llm_recorder.get_record("20261009T000000Z_01234567_m1_999.json") is None  # 不存在


# ---- 轮转 ----

def test_rotation_keeps_only_latest(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_RECORD_KEEP", "10")  # 下限 10
    for i in range(15):
        _rec(model=f"rot{i:02d}")
    files = [n for n in os.listdir(os.path.join(str(tmp_path), "llm_records"))
             if n.endswith(".json") and n != "index.jsonl"]
    assert len(files) == 10
    # 索引不删（详情 404 无害）
    assert len(llm_recorder.list_records(limit=100)) == 15
