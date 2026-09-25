"""靶场档案 + 派发配方（已知靶场快通）。

- 靶场档案: data/targets/<target_id>.md（靶场特定情报: 地址/攻击面/漏洞位置/凭据）。
  打完自动沉淀漏洞地图 → 第二次打自动热启动，免用户重复描述。
- 派发配方: 已知靶场(有档案) + PIMETA_KNOWN_FAST=1 → 自动套快通配方
  (跳侦察/全派候选模块/提高并行+轮次/防过度验证文案)。未给项回退 env 默认。
"""
from __future__ import annotations

import os

from agents.orchestrator_v2 import TARGETS_DIR
from config import env as cfg_env


def profile_path(target_id: str) -> str:
    return os.path.join(TARGETS_DIR, f"{target_id}.md")


def target_profile_exists(target_id: str) -> bool:
    return bool(target_id) and os.path.exists(profile_path(target_id))


def resolve_recipe(target_id: str) -> dict:
    """已知靶场(有档案) + PIMETA_KNOWN_FAST=1 → 返回快通配方 dict；否则 {}（走 env 默认）。

    配方项: max_modules(候选模块数)/force_all(跳 root 剪枝全派)/skip_recon(跳侦察热启动)
    /max_parallel(并行子 agent)/child_max_turns(单子 agent 轮次上限)。
    全部 config 驱动(.env)，不 hardcode。
    """
    if cfg_env("PIMETA_KNOWN_FAST", "1") != "1":
        return {}
    if not target_profile_exists(target_id):
        return {}
    return {
        "max_modules": int(cfg_env("PIMETA_KNOWN_MAX_MODULES", "9")),
        "force_all": True,
        "skip_recon": True,
        "max_parallel": int(cfg_env("PIMETA_KNOWN_MAX_PARALLEL", "4")),
        "child_max_turns": int(cfg_env("PIMETA_KNOWN_CHILD_TURNS", "80")),
    }


def known_task_suffix() -> str:
    """已知靶场追加到 task 文本的防过度验证文案（防 child 满场游走/重复复验）。"""
    return cfg_env(
        "PIMETA_KNOWN_TASK_SUFFIX",
        "KNOWN TARGET: produce one clean PoC per module, then move on. "
        "Do NOT over-verify or re-test the same vulnerability.")


def build_target_profile(task_id: str, target: str, target_id: str) -> str | None:
    """任务 done 后，从 findings 自动生成该 target 的漏洞地图档案。

    只存中性 intel（地址/漏洞类/位置/严重度），不存 poc/证据/凭证（那些进 KB/漏洞板）。
    档案已存在则不覆盖（保留人工补充的凭据/网络）。返回档案路径；无有效 finding 或已存在则 None。
    """
    if not target_id or target_profile_exists(target_id):
        return None
    from . import report_builder
    findings = report_builder.query_findings(task_id)
    valid = [f for f in findings
             if str(f.get("status", "found")).lower() not in {"false_positive", "suspect"}]
    if not valid:
        return None

    rows, seen = [], set()
    for f in valid:
        vc = str(f.get("vuln_class") or "other")
        loc = str(f.get("location") or "")
        sev = str(f.get("severity") or "")
        key = (vc, loc)
        if key in seen:
            continue
        seen.add(key)
        rows.append((vc, loc, sev))

    classes = sorted({str(f.get("vuln_class") or "other") for f in valid})
    lines = [
        f"# {target_id} 靶场档案（自动生成）",
        "",
        f"> 由 {len(valid)} 条 findings 自动沉淀。首次人工补充登录凭据/网络后可删除此注。",
        "",
        "## 地址",
        f"- {target}",
        "",
        "## 攻击面 / 漏洞位置",
        "| 漏洞类 | 位置 | 严重度 |",
        "|---|---|---|",
    ]
    lines += [f"| {vc} | {loc} | {sev} |" for vc, loc, sev in rows]
    lines += [
        "",
        "## 已确认漏洞类（去重）",
        ", ".join(classes),
        "",
        "## 登录（首次需人工确认）",
        "- 凭据: TODO（首次打时确认默认/弱口令）",
        "",
    ]
    os.makedirs(TARGETS_DIR, exist_ok=True)
    path = profile_path(target_id)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path
