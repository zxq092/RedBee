from __future__ import annotations
import os, sqlite3, json, re, uuid
from datetime import datetime, timezone

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "redkb.db")

TECHNIQUE_PATTERNS = {
    "sqli": [r"SQL.*inject|UNION.*SELECT|' OR 1=1|blind.*inject|information_schema", r"sqli|SQLI"],
    "xss": [r"XSS|Cross.Site.*Script|onerror|onload.*alert|dom.*xss|stored.*xss|data-export", r"<script|<img.*onerror|<svg.*onload"],
    "jwt": [r"jwt|JWT|token.*forg|alg.*confus|HS256.*public|secret.*hard", r"header.*payload.*sign|decode.*token"],
    "ssrf": [r"SSRF|ssrf|profile.*image.*url|127\.0\.0\.1|internal.*endpoint|mirror.*oracle", r"fetch.*http.*127|redirect.*localhost"],
    "lfi": [r"LFI|lfi|null.byte|%2500|%00|file.*include|etc/passwd", r"path.*traversal|\.\.\/"],
    "xxe": [r"XXE|xxe|<!DOCTYPE|ENTITY.*SYSTEM|file:///etc|xml.*entity|multipart.*xml", r"complaint\.xml|DTD"],
    "csrf": [r"CSRF|csrf|cross.site.request.forgery|auto.submit|forged.*request|<form.*action", r"onerror.*submit"],
    "idor": [r"IDOR|idor|object.*reference|horizontal|basket.*read|access.*other.*user", r"user\/\d+|id=\d+|Param.*tamper"],
    "auth": [r"login.*bypass|admin.*regist|credential.*leak|password.*hash|auth.*bypass|default.*cred", r"authoriz.*bypass|privilege.*escalat"],
    "file_upload": [r"file.*upload|shell|php.*extension|mime.*type|Content.Type.*image|GIF89a|double.*ext", r"multipart.*upload"],
    "crypto": [r"crypto|weak.*hash|md5|crack|nyan.*cat|hardcoded.*secret|encryption", r"algorithm.*confus"],
    "deserialization": [r"deserial|Insecure.*Deserial|XStream|pickle|gadget|unsafe.*matcher", r"rce.*via.*deserial|object.*inject"],
    "business_logic": [r"negat.*quantity|basket.*manip|coupon.*forg|zero.*star|rating.*manip|ticket.*farm", r"price.*manip|checkout.*bypass"],
    "steganography": [r"steganograph|LSB|hidden.*image|pixel.*manip|carrier.*file", r"stegano|bit.*manip"],
    "typosquatting": [r"typosquat|typo.*squat|imposter.*package|near.by.*name|similar.*name.*package|vulnerable.*library", r"library.*version"],
    "recon": [r"directory.*enum|gobuster|dirsearch|hidden.*page|route.*enum|source.*code.*hint|info.disclosure", r"nmap|scan.*endpoint"],
}


def extract_techniques(task: str, summary: str, trajectory_str: str) -> list:
    text = (task or "") + " " + (summary or "") + " " + (trajectory_str or "")
    found = []
    for tech_type, patterns in TECHNIQUE_PATTERNS.items():
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                context = text[max(0, m.start() - 200):m.end() + 80].strip()
                context = re.sub(r'\s+', ' ', context)
                found.append({"technique_type": tech_type, "evidence": context[:400]})
                break
    return found


def create_entries(techniques: list, task: str, summary: str) -> list:
    entries = []
    for tech in techniques:
        ttype = tech["technique_type"]
        evidence = tech["evidence"]
        eid = "kb.distill." + uuid.uuid4().hex[:8]
        content = json.dumps({
            "method": [evidence],
            "expected": f"Target reveals {ttype} vulnerability",
            "verify": f"Run technique and confirm {ttype} exists",
            "preconditions": f"Target has {ttype}-class vulnerability",
            "bypass_techniques": [],
        }, ensure_ascii=False)
        tags = [ttype, "auto-distilled", "agent-derived"]
        entries.append((
            eid, "attack_primitive",
            f"Auto-distilled {ttype} - flow-extract",
            content, json.dumps(tags), "all", "candidate",
            False, "agent", "agent-distillation",
            f"Target has {ttype}-class vulnerability", 0.5,
            f"#{ttype}",
            datetime.now(timezone.utc).isoformat(),
            datetime.now(timezone.utc).isoformat(), 0.0,
            task,
        ))
    return entries


class Distiller:
    def __init__(self, db_path: str = DB):
        self.db_path = db_path

    def get_new_cases(self) -> list:
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        existing_tasks = set()
        for row in c.execute("SELECT distilled_from FROM knowledge WHERE distilled_from IS NOT NULL"):
            existing_tasks.add(row[0])
        new_cases = []
        for row in c.execute("SELECT task, summary, trajectory FROM cases ORDER BY created_at DESC"):
            if row["task"] and row["task"] not in existing_tasks:
                new_cases.append(dict(row))
        c.close()
        return new_cases

    def distill_case(self, case: dict) -> list:
        techniques = extract_techniques(
            case.get("task", ""),
            case.get("summary", ""),
            case.get("trajectory", "") or "",
        )
        return [create_entries([t], case["task"], case["summary"] or "")[0] for t in techniques]

    def insert_entries(self, entries: list) -> int:
        if not entries:
            return 0
        c = sqlite3.connect(self.db_path)
        count = 0
        for entry in entries:
            try:
                c.execute("""INSERT OR IGNORE INTO knowledge
                    (id, type, title, content, tags, scope, status, verified, proof_method,
                     source_type, preconditions, confidence, coverage_state,
                     created_at, updated_at, success_rate, distilled_from)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", entry)
                count += 1
            except sqlite3.IntegrityError:
                pass
        c.commit()
        c.close()
        return count

    def run(self) -> dict:
        new_cases = self.get_new_cases()
        all_entries = []
        for case in new_cases:
            entries = self.distill_case(case)
            all_entries.extend(entries)
        inserted = self.insert_entries(all_entries)
        return {
            "new_cases_processed": len(new_cases),
            "techniques_extracted": len(all_entries),
            "new_entries_inserted": inserted,
            "existing_entries_skipped": len(all_entries) - inserted,
        }


if __name__ == "__main__":
    result = Distiller().run()
    print(json.dumps(result, ensure_ascii=False, indent=2))
