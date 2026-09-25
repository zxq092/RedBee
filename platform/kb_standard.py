#!/usr/bin/env python3
"""专家级知识标准: 把裸 payload 升级为完整 attack_primitive 结构.

核心原则(像人积累专家知识):
  一条可用攻击知识 = {method(手法), expected(预期), verify(判别逻辑),
                       preconditions(前置), bypass_techniques(绕过)}

RED-KB 的 attack_primitive 类型本来就为此设计, 但果汁那批是 poc(裸payload)。
本脚本:
  1. 读取候选 poc 条目
  2. 从 payload/端点自动推导 expected/verify/preconditions
  3. 按 attack_primitive 结构入库(默认 candidate, 避免盲目 authoritative)

用法:
  python3 kb_standard.py --dry-run        # 预览推导结果
  python3 kb_standard.py                  # 实际上库
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid

import httpx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
REDKB_URL = os.environ.get("REDKB_URL", "http://127.0.0.1:8001")

# 技法 -> 判别逻辑(verify) 与 前置(preconditions) 专家模板
EXPERT = {
    "sqli": {
        "verify": "观察响应: 注入参数值导致报错/布尔差异/时间延迟, 或 union 列数匹配后回显额外数据列",
        "preconditions": "目标存在未参数化的 SQL 拼接(搜索/登录/排序等参数点)",
        "expected": "执行注入语句, 泄露数据或绕过认证",
        "bypass": ["WAF 过滤时用注释符/大小写/编码变体", "盲注用时间或布尔判别"],
    },
    "jwt": {
        "verify": "用伪造 token 请求需认证接口返回 200/数据(对比未认证的 401/重定向)",
        "preconditions": "服务端用 JWT 做认证, 且存在密钥可猜/算法可混淆/未校验签名",
        "expected": "伪造合法 token 冒充任意用户/管理员",
        "bypass": ["改 alg 为 none", "HS256/RSA 算法混淆", "用泄露的硬编码密钥重签"],
    },
    "xxe": {
        "verify": "XML 中嵌入外部实体, 响应回显文件内容(file:///etc/passwd)或外带请求",
        "preconditions": "存在解析 XML 的端点且未禁用外部实体",
        "expected": "任意文件读取 / SSRF / DoS",
        "bypass": ["参数实体绕过", "编码(XML/UTF-16)绕过过滤器", "billion-laughs DoS"],
    },
    "lfi": {
        "verify": "路径参数注入 ../ 或 null字节, 响应回显服务器文件内容",
        "preconditions": "文件路径参数未过滤 ../ 或目录穿越符",
        "expected": "任意文件读取",
        "bypass": ["双 URL 编码 %2500", "编码../", "路径规范化"],
    },
    "ssrf": {
        "verify": "将 URL 参数指向内部地址(127.0.0.1/内网), 响应回显内部内容或触发内网请求",
        "preconditions": "服务端存在可提供 URL 下载/抓取的端点",
        "expected": "访问内部服务/元数据",
        "bypass": ["DNS rebinding", "IP 编码变体", "重定向跟随"],
    },
    "nosql": {
        "verify": "JSON 参数注入操作符($gt/$ne/$regex), 返回越权/额外数据或报错",
        "preconditions": "后端用 NoSQL(如 MongoDB)且直接拼接 JSON 操作符",
        "expected": "越权读取/注入操作符",
        "bypass": ["操作符嵌套", "$where 执行", "数组注入"],
    },
    "xss": {
        "verify": "输入脚本在响应中未编码回显, 且浏览器执行(onerror/alert)",
        "preconditions": "用户输入未过滤即渲染到 HTML/JS 上下文",
        "expected": "执行任意脚本/窃取会话",
        "bypass": ["过滤绕过编码", "DOM-based", "属性/事件上下文"],
    },
    "rce": {
        "verify": "注入的命令/反序列化 payload 在服务端执行(如 ping 回显/延时/写文件)",
        "preconditions": "存在命令拼接注入或不安全反序列化",
        "expected": "任意命令执行",
        "bypass": ["命令分隔符", "编码", "无回显用延时盲打"],
    },
    "ssti": {
        "verify": "模板表达式({{7*7}}等)在响应中求值并回显结果",
        "preconditions": "服务端模板引擎渲染用户输入",
        "expected": "表达式执行 → RCE",
        "bypass": ["过滤绕过", "多引擎探测"],
    },
    "deserialization": {
        "verify": "提交序列化对象触发反序列化执行(报错/延时/命令执行)",
        "preconditions": "存在反序列化用户输入且不安全",
        "expected": "RCE / DoS",
        "bypass": ["gadget 构造", "编码绕过"],
    },
    "crypto": {
        "verify": "弱算法/弱密钥可被破解或伪造(如爆hash、预测token、伪造coupon)",
        "preconditions": "使用了弱加密/可预测方案",
        "expected": "伪造/解密/绕过",
        "bypass": ["已知明文", "密钥复用", "算法降级"],
    },
    "auth": {
        "verify": "绕过认证流程成功获得受限访问或伪造凭据",
        "preconditions": "认证逻辑存在缺陷(弱口令/可预测/逻辑绕过)",
        "expected": "绕过认证/提升权限",
        "bypass": ["逻辑绕过", "参数污染", "会话固定"],
    },
    "mass_assignment": {
        "verify": "请求中注入额外字段(如 role=admin), 服务器接受并生效",
        "preconditions": "后端模型未白名单化字段, 直接绑定请求参数",
        "expected": "越权设置属性",
        "bypass": ["加嵌套 JSON", "改 Content-Type"],
    },
    "csrf": {
        "verify": "无 CSRF token 的敏感操作可用第三方页面发起",
        "preconditions": "关键操作缺少 CSRF token 校验",
        "expected": "诱导受害者执行操作",
        "bypass": ["Origin 校验绕过", "同源漏洞"],
    },
    "idor": {
        "verify": "修改对象 ID 访问他人资源返回数据",
        "preconditions": "资源访问未校验所有者",
        "expected": "越权访问对象",
        "bypass": ["ID 枚举", "整数溢出", "UUID 可预测"],
    },
}

TECH_HINT = [
    (r"union|sql inject|\bq=.*'\b|blind", "sqli"),
    (r"jwt|hs256|alg.*confus|unsigned|eyJ", "jwt"),
    (r"xxe|doctype|xml entit|billion|/file-upload.*xml", "xxe"),
    (r"lfi|null.?byte|%2500|%00|/ftp|etc/passwd|travsers|\.\./", "lfi"),
    (r"ssrf|image.?url|127\.0\.0\.1|/profile/image|fetch.*http", "ssrf"),
    (r"nosql|\$gt|\$ne|mongo|/rest/basket", "nosql"),
    (r"xss|<script|onerror|alert\(|innerHTML|/search\?q|feedback", "xss"),
    (r"rce|child_process|command|/b2b|system\(|deserial", "rce"),
    (r"ssti|{{|\$\{|jinja|template", "ssti"),
    (r"deserial|b2b.*order|serializ", "deserialization"),
    (r"coupon|crypto|z85|weak.?hash|md5", "crypto"),
    (r"login|password|2fa|totp|reset|auth", "auth"),
    (r"role.?admin|mass.assign|register", "mass_assignment"),
    (r"csrf|forgery|referer", "csrf"),
    (r"user/\d+|basket/\d+|review.*other", "idor"),
]


def tech_of(text: str) -> str:
    for pat, t in TECH_HINT:
        if re.search(pat, text, re.I):
            return t
    return "unknown"


def build_primitive(tech: str, method_text: str, evidence: str = "") -> dict:
    ex = EXPERT.get(tech, {
        "verify": "观察响应是否符合漏洞预期特征(报错/回显/状态异常)",
        "preconditions": "存在对应的脆弱代码路径",
        "expected": "触达目标资产或泄露信息",
        "bypass": [],
    })
    return {
        "method": method_text or "",
        "expected": ex["expected"],
        "verify": ex["verify"],
        "preconditions": ex["preconditions"],
        "bypass_techniques": ex["bypass"],
        "evidence": evidence or "",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()

    kb = httpx.get(f"{REDKB_URL}/kb/list", timeout=20).json()
    # 只处理 poc 类型且含真实 payload 的候选
    cand = [e for e in kb
            if e.get("type") == "poc"
            and not e.get("disabled", 0)
            and e.get("status") != "disabled"
            and ('PentAGI extracted' in str(e.get('title',''))
                 or 'auto-report-poc' in str(e.get('tags','')))]
    print(f"候选 poc 条目: {len(cand)}")

    upgraded = 0
    for e in cand:
        try:
            c = json.loads(e.get("content") or "{}")
        except Exception:
            continue
        m = c.get("method", "")
        if isinstance(m, list):
            m = m[0] if m else ""
        m = str(m)
        if not m or len(m) < 15:
            continue
        tech = tech_of(m)
        prim = build_primitive(tech, m, c.get("verify", ""))
        entry = {
            "id": f"kb.standard.{tech}.{uuid.uuid4().hex[:6]}",
            "type": "attack_primitive",
            "scope": "all",
            "title": f"[standard] {tech}: {m[:55]}",
            "content": json.dumps(prim, ensure_ascii=False),
            "tags": [tech, "attack-primitive", "standard"],
            "status": "candidate",
            "verified": False,
            "source_type": "kb-standard",
            "case_evidence": list(dict.fromkeys(e.get("case_evidence", []))),
            "confidence": 0.85,
        }
        if a.dry_run:
            upgraded += 1
            if upgraded <= 6:
                print(f"  [{tech}] {m[:55]}")
                print(f"       verify: {prim['verify'][:60]}")
        else:
            r = httpx.post(f"{REDKB_URL}/kb/ingest", json=entry, timeout=15)
            if r.status_code in (200, 201):
                upgraded += 1
    print(f"\n升级为 attack_primitive: {upgraded} 条" if not a.dry_run else f"(dry-run) 可达 {upgraded} 条")


if __name__ == "__main__":
    main()
