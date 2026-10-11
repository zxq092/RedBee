"""Injection 子类拆模块：lfi/xxe/xpath 作为一等模块（planner + skill alias + phrasing 解析）。"""
import pytest


def test_new_modules_in_planner():
    from pi_meta.planner import MODULES, modules_for
    for m in ("lfi", "xxe", "xpath"):
        assert m in MODULES
    # 传统靶场（非 LLM）候选里含这三个
    cand = modules_for("http://t", "task", "other", max_modules=12)
    assert {"lfi", "xxe", "xpath"}.issubset(cand)


def test_skill_alias_resolves_for_new_modules():
    from agents.tools import resolve_skill_name, get_skill_content
    expected = {"lfi": "path-traversal-lfi-rfi", "xxe": "xxe", "xpath": "xpath-injection"}
    for m, skill in expected.items():
        assert resolve_skill_name(m) == skill
        assert get_skill_content(m), f"{m} 应命中 skill"


def test_validate_task_params_accepts_new_modules():
    from pi_meta.real_dispatch import validate_task_params
    from pi_meta.planner import MODULES
    out, errs = validate_task_params({"modules": "lfi,xxe,xpath"})
    assert not errs
    assert out["modules"] == ["lfi", "xxe", "xpath"]


def test_mutillidae_profile_recipe_includes_new_modules(monkeypatch):
    """已知靶场快通配方 max_modules 应覆盖新模块（默认 12）。"""
    import pi_meta.target_profile as tp
    monkeypatch.setattr(tp, "target_profile_exists", lambda tid: True)
    monkeypatch.setattr(tp, "cfg_env", lambda k, d="": ({"PIMETA_KNOWN_FAST": "1"}.get(k, d)))
    recipe = tp.resolve_recipe("mutillidae")
    assert recipe.get("max_modules", 0) >= 12
