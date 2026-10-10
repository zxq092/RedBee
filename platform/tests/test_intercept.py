from __future__ import annotations

import json

import pytest

import asyncio

import agents.tools as tools_mod
from agents import intercept


def check(tool: str, args: dict, task_id: str = "t1"):
    """同步测试包装：intercept_check 是 async（executor 里 await）。"""
    return asyncio.run(intercept.intercept_check(tool, args, task_id))


@pytest.fixture(autouse=True)
def _tmp_intercept_db(tmp_path, monkeypatch):
    monkeypatch.setattr(tools_mod, "DB_PATH", str(tmp_path / "pimeta_test.db"))
    intercept._compiled_cache.clear()
    yield
    intercept._compiled_cache.clear()
    intercept._pending.clear()


def test_seed_rules_loaded_once():
    rules = intercept.list_rules()
    assert len(rules) == 21
    enabled = [r for r in rules if r["enabled"]]
    assert len(enabled) == 20  # 数据外泄管道 ARTEX 默认禁用（误报率）
    names = {r["name"] for r in rules}
    assert "[内置] 递归强制删除 rm -rf" in names
    assert "[内置] 删除类接口路径" in names
    # 幂等：再连一次不重复灌
    assert len(intercept.list_rules()) == 21


def test_deny_blocks_destructive_command():
    res = check("bash", {"command": "sudo rm -rf /"}, "t1")
    assert res is not None
    assert "intercepted" in res and "error" in res
    # 审计落库
    hist = intercept.list_history(task_id="t1")
    assert any(h["status"] == "denied" and h["tool_name"] == "bash" for h in hist)


def test_benign_command_passes():
    assert check("bash", {"command": "nmap -F target"}, "t1") is None
    assert check("bash", {"command": "ls -la /home"}, "t1") is None


def test_non_scanned_tool_not_blocked():
    """submit_finding 的证据文本含危险命令字符串也不能误伤（只扫命令面工具）。"""
    res = check(
        "submit_finding",
        {"title": "cmd injection", "poc": "echo `rm -rf /`", "evidence": "DROP TABLE users"},
        "t1")
    assert res is None


def test_tool_filter_configurable(monkeypatch):
    monkeypatch.setenv("HINSE_INTERCEPT_TOOLS", "bash")
    assert intercept._scan_tools() == {"bash"}
    # python 工具不再扫 → 含 DELETE 的 python 代码放行
    assert check(
        "python", {"code": "import requests; requests.delete('http://t/x')"}, "t1") is None


def test_disabled_engine_passes_everything(monkeypatch):
    monkeypatch.setenv("HINSE_INTERCEPT_ENABLED", "0")
    assert check("bash", {"command": "mkfs.ext4 /dev/sda1"}, "t1") is None


def test_sql_rules_match_command_surface():
    assert check(
        "bash", {"command": "mysql -e 'DROP TABLE users'"}, "t1") is not None
    assert check(
        "terminal", {"command": "redis-cli FLUSHALL"}, "t1") is not None


def test_http_request_delete_method_blocked():
    res = check(
        "http_request", {"url": "http://t/api/users", "method": "DELETE"}, "t1")
    assert res is not None
    res2 = check(
        "http_request", {"url": "http://t/api/users/1/delete", "method": "POST"}, "t1")
    assert res2 is not None  # 删除类接口路径规则（不限 method）


@pytest.mark.asyncio
async def test_allow_rule_overrides_deny():
    rid = intercept.upsert_rule(
        None, "白名单-允许删除", r"rm\s+-rf\s+/var/www/allow", "allow", priority=200)
    try:
        # 200 > 100：allow 先命中 → 放行（即便 rm -rf deny 规则也能匹配）
        assert await intercept.intercept_check(
            "bash", {"command": "rm -rf /var/www/allow/site"}, "t1") is None
        # 审计里记 allowed
        assert any(h["status"] == "allowed" for h in intercept.list_history(task_id="t1"))
    finally:
        intercept.delete_rule(rid)


@pytest.mark.asyncio
async def test_ask_waits_for_human_decision():
    rid = intercept.upsert_rule(
        None, "测试-审批", r"\bdropbox_sync\b", "ask", priority=150,
        message="需要人工确认")
    try:
        done = False

        async def checker():
            nonlocal done
            res = await intercept.intercept_check(
                "bash", {"command": "dropbox_sync --push"}, "t1")
            done = True
            return res

        import asyncio
        task = asyncio.create_task(checker())
        await asyncio.sleep(0.1)
        assert not done  # 阻塞中
        pending = intercept.list_pending(task_id="t1")
        assert len(pending) == 1
        did = pending[0]["id"]
        assert intercept.decide_decision(did, "allow", "OK")
        res = await asyncio.wait_for(task, timeout=5)
        assert res is None  # 批准 → 放行
        assert all(p["status"] == "allowed" for p in intercept.list_history(task_id="t1")
                   if p["rule_id"] == rid)
    finally:
        intercept.delete_rule(rid)


@pytest.mark.asyncio
async def test_ask_deny_verdict_blocks():
    rid = intercept.upsert_rule(None, "测试-审批2", r"\bnuke_target\b", "ask", priority=150)
    try:
        import asyncio
        task = asyncio.create_task(intercept.intercept_check(
            "bash", {"command": "nuke_target --all"}, "t1"))
        await asyncio.sleep(0.1)
        did = intercept.list_pending(task_id="t1")[0]["id"]
        intercept.decide_decision(did, "deny", "不行")
        res = await asyncio.wait_for(task, timeout=5)
        assert res is not None and "审批未通过" in res["error"]
    finally:
        intercept.delete_rule(rid)


@pytest.mark.asyncio
async def test_ask_timeout_denies(monkeypatch):
    monkeypatch.setenv("HINSE_INTERCEPT_ASK_TIMEOUT", "1")
    rid = intercept.upsert_rule(None, "测试-审批3", r"\bslow_approval\b", "ask", priority=150)
    try:
        import asyncio
        res = await asyncio.wait_for(
            intercept.intercept_check("bash", {"command": "slow_approval"}, "t1"), timeout=10)
        assert res is not None and "审批未通过" in res["error"]
        hist = [h for h in intercept.list_history(task_id="t1") if h["rule_id"] == rid]
        assert hist and hist[0]["status"] == "denied" and "timeout" in hist[0]["decided_by"]
    finally:
        intercept.delete_rule(rid)


@pytest.mark.asyncio
async def test_ask_race_decide_before_wait_registered():
    """decide 在 INSERT 之后、future 注册之前到达 → 注册后重读库不丢裁决（ARTEX 同款竞态）。"""
    rid = intercept.upsert_rule(None, "测试-竞态", r"\brace_check\b", "ask", priority=150)
    try:
        import asyncio

        async def pre_decide():
            await asyncio.sleep(0.05)
            pending = [p for p in intercept.list_pending(task_id="t1") if p["rule_id"] == rid]
            if pending:
                intercept.decide_decision(pending[0]["id"], "allow")

        watcher = asyncio.create_task(pre_decide())
        res = await asyncio.wait_for(
            intercept.intercept_check("bash", {"command": "race_check now"}, "t1"), timeout=10)
        await watcher
        assert res is None  # 批准未被吞掉
    finally:
        intercept.delete_rule(rid)


def test_rule_validation_and_crud():
    with pytest.raises(ValueError):
        intercept.upsert_rule(None, "bad", "([unclosed", "deny")
    with pytest.raises(ValueError):
        intercept.upsert_rule(None, "bad", "a", "explode")
    rid = intercept.upsert_rule(None, "临时规则", r"\btemp_xyz\b", "deny")
    assert any(r["id"] == rid for r in intercept.list_rules())
    intercept.upsert_rule(rid, "临时规则改名", r"\btemp_xyz2\b", "ask", enabled=False)
    rules = {r["id"]: r for r in intercept.list_rules()}
    assert rules[rid]["action"] == "ask" and rules[rid]["enabled"] == 0
    assert intercept.delete_rule(rid)
    assert not intercept.delete_rule(rid)


def test_invalid_regex_rule_ignored_not_fatal():
    """upsert 入口会拒绝坏正则；但库里若已有（历史数据/手改），检查时跳过不致命。"""
    with pytest.raises(ValueError):
        intercept.upsert_rule(None, "bad", "([unclosed", "deny")
    conn = intercept._conn()
    cur = conn.execute(
        "INSERT INTO intercept_rules (name, enabled, priority, pattern, action, message, created_at) "
        "VALUES ('坏正则但已入库', 1, 50, '(?<bad-lookbehind>', 'deny', '', 'x')")
    conn.commit()
    bad_id = cur.lastrowid
    conn.close()
    try:
        # 坏正则规则被跳过，不阻塞、不影响其他规则
        assert check("bash", {"command": "ls"}, "t1") is None
        assert check("bash", {"command": "mkfs /dev/sda"}, "t1") is not None
    finally:
        intercept.delete_rule(bad_id)
