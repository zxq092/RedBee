"""Cajac/picoCTF-Writeups 摄取（数据工厂题源 3，2026-10-21）。

结构：<Event>/<Category>/<Challenge>.md（md-per-题，含 Level/Points/Description/Hints/Solution/flag）。
策略（HHousen 难题集教训 → 易题优先）：
- 服务型题（nc/ssh/webshell/start instance）跳过
- 附件在兄弟目录（Images/ 等）稀少；**描述内嵌数据题**（caesar/2Warm/Bases 类：
  谜面就在 Description 里的编码串）→ 数据块落成 data.txt 工件，统一走工件管道
- 只收 Level ∈ {Easy, Medium} 或 Points ≤ 200，按分值升序 cap 30
- 按 题名slug 与现有 spec 去重

用法：python3 -m benchmark.cajac_ingest [--src /tmp/opencode/cajac] [--cap 30] [--dry]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

SRC = Path("/tmp/opencode/cajac")
SERVE_ROOT = Path("/tmp/opencode/cyb_tasks")
SPEC = Path(__file__).resolve().parents[2] / "data" / "benchmark" / "picoctf_tasks.json"
FLAG_RE = re.compile(r"picoCTF\{[^}\s]{4,}\}")
NEEDS_LIVE = re.compile(r"\bnc\s+\S+|ssh\s+-p|webshell|start your instance|connect to (?:the )?(?:program|game|service)", re.I)
# 描述内嵌数据启发：长 base64ish / hex / 二进制串
DATA_BLOB = re.compile(r"(?<![\w/:.])[A-Za-z0-9+/]{16,}={0,2}(?![\w/:.]|[.]/)|(?<![\w])https?://\S+|(?<![\w])[0-9a-fA-F]{20,}(?![\w])|(?<![\w])[01]{20,}(?![\w])")
_URL = re.compile(r"^https?://|/")


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40]


def parse_md(md: Path) -> dict | None:
    text = md.read_text(errors="ignore")
    if not FLAG_RE.search(text):
        return None
    m = re.search(r"## Challenge information\s*```text(.*?)```", text, re.S)
    if not m:
        return None
    info = m.group(1)
    lvl = (re.search(r"Level:\s*(\w+)", info) or [None, "?"])[1]
    pts = re.search(r"Points:\s*(\d+)", info)
    pts = int(pts.group(1)) if pts else 0
    d = re.search(r"Description:\s*(.*?)(?:\n\s*\n\s*Hints:|\n\s*Hints:|$)", info, re.S)
    desc = (d.group(1).strip() if d else "").strip()
    h = re.search(r"Hints:\s*(.*?)(?:Challenge link:|$)", info, re.S)
    hints = [ln.strip(" -)0123456789").strip() for ln in (h.group(1) if h else "").splitlines() if ln.strip()][:3]
    if NEEDS_LIVE.search(info):
        return None
    if md.parent.name == "Web_Exploitation" and not any(
            sib.is_file() and sib.suffix.lower() in (".zip", ".txt", ".py")
            for sib in md.parent.iterdir()):
        return None  # web 题要打活网站，工件域打不了（有真附件的例外）
    if lvl not in ("Easy", "Medium") and pts > 200:
        return None
    # 数据工件：兄弟附件（若有）或描述内嵌数据块
    files_src = []
    for sib in sorted(md.parent.iterdir()) if md.parent.exists() else []:
        if sib.is_file() and sib.suffix.lower() in (".jpg", ".jpeg", ".png", ".gif", ".zip", ".txt", ".pcap", ".pcapng", ".wav", ".py", ".csv"):
            files_src.append(sib)
    # 数据工件：兄弟附件（若有）或描述内嵌数据块。
    # ⚠️ 必须在原始 desc（保留空格）上匹配——去空格会把普通句子粘成 16+ 字符伪数据块
    blob = DATA_BLOB.search(desc)
    if blob and (_URL.match(blob.group(0)) or blob.group(0).startswith("http")):
        blob = None  # URL 不是数据块
    return {"stem": md.stem, "category": md.parent.name, "level": lvl, "points": pts,
            "desc": desc[:240], "hints": hints, "files_src": files_src,
            "data_blob": blob.group(0) if blob and not files_src else "",
            "flag": FLAG_RE.findall(text)[-1]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(SRC))
    ap.add_argument("--cap", type=int, default=30)
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    existing = json.loads(SPEC.read_text(encoding="utf-8")) if SPEC.exists() else []
    have_ids = [t["id"] for t in existing]
    rows = []
    for md in Path(args.src).rglob("*.md"):
        if md.stem.lower() == "readme":
            continue
        r = parse_md(md)
        if not r:
            continue
        slug = _slug(r["stem"])
        if any(eid.endswith(slug) for eid in have_ids):
            continue
        if not r["files_src"] and not r["data_blob"]:
            continue  # 无文件且无内嵌数据 → 离线推不出
        r["slug"] = slug
        rows.append(r)
    rows.sort(key=lambda x: (x["points"], x["level"] != "Easy"))
    rows = rows[:args.cap]
    print(f"Cajac 候选 {len(rows)} 题（易题优先 cap={args.cap}）")
    new_spec = []
    for r in rows:
        event = r and Path()
        cid = f"picogym-{r['slug']}"
        if args.dry:
            print(f"  [{r['points']:>3}pts/{r['level'][:6]:<6}] {r['category']:<20} {r['stem']} files={len(r['files_src'])} blob={'Y' if r['data_blob'] else 'n'}")
            continue
        dest = SERVE_ROOT / cid
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        for f in r["files_src"]:
            shutil.copy2(f, dest / f.name)
        if r["data_blob"]:
            (dest / "data.txt").write_text(r["data_blob"], encoding="utf-8")
        new_spec.append({"id": cid, "category": r["category"], "points": r["points"],
                         "url": f"http://127.0.0.1:8901/{cid}/",
                         "sandbox_url": f"http://172.17.0.1:8901/{cid}/",
                         "flag": r["flag"], "desc": r["desc"], "hints": r["hints"]})
    if not args.dry:
        SPEC.write_text(json.dumps(existing + new_spec, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"spec 追加 {len(new_spec)} 题 → 总 {len(existing) + len(new_spec)}")


if __name__ == "__main__":
    main()
