from __future__ import annotations

"""Tests for the Web/meta layer additions:
- ModelRouter runtime override (manual model switch) + clear + validation
- web_auth token issuance / validation / expiry (optional auth)
"""

import time

import pytest

from pi_meta.model_router import ModelRouter


def test_router_override_roundtrip():
    r = ModelRouter(priority=["DeepSeek-V4-Flash", "qwen3.8-27b"])
    assert r.override is None
    assert r.model_priority == ["DeepSeek-V4-Flash", "qwen3.8-27b"]

    r.set_override("qwen3.8-27b")
    assert r.override == "qwen3.8-27b"
    assert r.model_priority == ["qwen3.8-27b"]

    r.clear_override()
    assert r.override is None
    assert r.model_priority == ["DeepSeek-V4-Flash", "qwen3.8-27b"]


def test_router_override_multiple_valid():
    r = ModelRouter(priority=["a"])
    r.set_override("m1,m2,m3")
    assert r.model_priority == ["m1", "m2", "m3"]


@pytest.mark.parametrize("bad", ["bad model", "a;b", "a b", "", "  "])
def test_router_override_invalid(bad):
    r = ModelRouter(priority=["a"])
    with pytest.raises(ValueError):
        r.set_override(bad)


def test_web_auth_disabled(monkeypatch):
    from pi_meta import web_auth

    monkeypatch.setattr("pi_meta.web_auth.WEB_TOKEN", "")
    assert web_auth.auth_enabled() is False
    assert web_auth.check_session("anything") is True
    assert web_auth.issue_session("anything") is None


def test_web_auth_enabled_lifecycle(monkeypatch):
    from pi_meta import web_auth

    monkeypatch.setattr("pi_meta.web_auth.WEB_TOKEN", "secret")
    assert web_auth.auth_enabled() is True
    assert web_auth.issue_session("wrong") is None
    tok = web_auth.issue_session("secret")
    assert tok
    assert web_auth.check_session(tok) is True
    # None value (unsupported) rejected
    assert web_auth.issue_session(None) is None


def test_web_auth_expiry(monkeypatch):
    from pi_meta import web_auth

    monkeypatch.setattr("pi_meta.web_auth.WEB_TOKEN", "secret")
    tok = web_auth.issue_session("secret")
    assert tok
    # force expiry
    web_auth._sessions[tok] = time.time() - 1
    assert web_auth.check_session(tok) is False
