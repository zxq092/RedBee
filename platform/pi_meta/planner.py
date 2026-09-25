"""Planner: 把目标拆成攻击模块清单(初始为固定 OWASP 清单, 按优先级排序)。

TODO(KB 细化): 用 LLM 读目标指纹 + 查 RED-KB, 动态裁剪/排序模块
(例如目标无文件上传功能就去掉 upload 模块)。当前先用固定清单 + 数量上限,
保证 MVP 行为可预期。
"""
from __future__ import annotations

import os

# 模块 -> 一句话攻击面描述(拼进派发 prompt)。顺序 = 派发优先级。
MODULES = {
    "llm": "LLM/AI application security: prompt injection, system prompt leak, sensitive disclosure, "
           "excessive agency, supply chain/poisoning, RAG/vector ACL, output handling (XSS), sycophancy, unbounded consumption",
    "sqli": "SQL injection: error/union/blind/time-based on every parameter and auth form",
    "xss": "Cross-site scripting: reflected / stored / DOM on every input",
    "auth": "Authentication & session: brute force, weak/default creds, session issues, privilege escalation, password reset",
    "upload": "File upload & file inclusion: extension/type bypass, LFI/RFI, path traversal",
    "cmdi": "Command injection / RCE: shell parameters, deserialization, template injection",
    "ssrf": "SSRF: URL parameters, webhooks, image/proxy fetch, cloud metadata",
    "idor": "Broken access control / IDOR: object references, function-level auth, mass assignment",
    "csrf": "CSRF & related: token bypass, CORS misconfig, open redirect",
    "misconfig": "Information disclosure & misconfig: exposed secrets, debug endpoints, default creds, security headers, backup files",
}

MAX_MODULES = int(os.environ.get("PIMETA_MAX_MODULES", "4"))

# LLM/AI 安全靶场：攻击面是 prompt/模型交互，不是传统 Web 漏洞 → 只派 llm 模块。
LLM_TARGETS = {"llmvault"}


def modules_for(target: str, task: str, target_id: str = "", max_modules: int | None = None) -> list[str]:
    """返回本次任务要打的攻击模块(受 PIMETA_MAX_MODULES 上限约束)。

    LLM/AI 靶场(见 LLM_TARGETS)只派 llm 模块——其攻击面是 prompt 注入/模型交互，
    传统 OWASP Web 模块(sqli/xss/...)不适用。
    传统靶场排除 llm 模块(那是 LLM 靶场专用)，只派 OWASP Web 模块。
    max_modules 显式传值时覆盖 env 上限(已知靶场快通用)。
    """
    if target_id in LLM_TARGETS:
        return ["llm"]
    limit = max_modules if max_modules is not None else MAX_MODULES
    return [m for m in MODULES if m != "llm"][:limit]
