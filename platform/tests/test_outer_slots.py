"""外层槽位模块数回归测试：v2 引擎内部已全模块 fan-out，外层只开 1 槽。

R10 实证：旧版外层 fan-out 9 个模块槽位 × 每槽重跑全部 9 模块 v2 流水线
= 9 倍冗余重跑（2 波×9=18 个子 agent 烧掉 90min 预算）。
"""


def test_outer_slot_modules_v2_single(monkeypatch):
    from pi_meta import orchestrator
    monkeypatch.setenv("HINSE_V2", "1")
    mods = orchestrator.outer_slot_modules("http://127.0.0.1:8081", "全模块渗透", "dvwa")
    assert len(mods) == 1


def test_outer_slot_modules_v1_full(monkeypatch):
    from pi_meta import orchestrator
    monkeypatch.setenv("HINSE_V2", "0")
    mods = orchestrator.outer_slot_modules("http://127.0.0.1:8081", "全模块渗透", "dvwa")
    assert len(mods) >= 2


def test_outer_slot_modules_llm_target_single(monkeypatch):
    # LLM 靶场：modules_for 本来就只返回 ["llm"]，v2 下仍是 1
    from pi_meta import orchestrator
    monkeypatch.setenv("HINSE_V2", "1")
    mods = orchestrator.outer_slot_modules("http://127.0.0.1:5001", "llm", "llmvault")
    assert mods == ["llm"]
