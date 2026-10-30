"""picoCTF 题库摄取（数据工厂 v1，2026-10-21）。

源：writeup 镜像仓（默认 vivian-dai/PicoCTF2021-Writeup，41 题，
<Category>/<Challenge>/README.md + 附件；README 含 Challenge Description/Hints/Solution/flag）。

产出：
- 玩家视角工件目录 /tmp/opencode/cyb_tasks/<pico-id>/（剔除 README.md 与题解脚本——
  脚本识别 = 文件内容前几行出现在 README 代码块中）
- spec data/benchmark/picoctf_tasks.json = [{id,url,sandbox_url,flag,desc,hints,category,points,offline}]

用法：python3 -m benchmark.pico_ingest [--src /tmp/opencode/pico2021] [--dry]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

SRC = Path("/tmp/opencode/pico2021")
SERVE_ROOT = Path("/tmp/opencode/cyb_tasks")
SPEC = Path(__file__).resolve().parents[2] / "data" / "benchmark" / "picoctf_tasks.json"
FLAG_RE = re.compile(r"picoCTF\{[^}\s]{4,}\}")


def _sections(readme: str) -> dict:
    """按 ## 标题切节。"""
    out: dict[str, str] = {}
    cur, buf = "", []
    for line in readme.splitlines():
        m = re.match(r"^##\s+(.+)$", line.strip())
        if m:
            if cur:
                out[cur] = "\n".join(buf).strip()
            cur, buf = m.group(1).strip(), []
        elif cur:
            buf.append(line)
    if cur:
        out[cur] = "\n".join(buf).strip()
    return out


def _extract_flag(readme: str) -> str:
    """flag 提取：唯一去重 → 唯一直接用；多个时优先 'Flag' 节里的；否则取最后出现。"""
    all_hits = FLAG_RE.findall(readme)
    if not all_hits:
        return ""
    uniq = []
    for f in all_hits:
        if f not in uniq:
            uniq.append(f)
    if len(uniq) == 1:
        return uniq[0]
    secs = _sections(readme)
    for key, body in secs.items():
        if "flag" in key.lower():
            in_flag = FLAG_RE.findall(body)
            if len(set(in_flag)) == 1:
                return in_flag[0]
    return all_hits[-1]


def _code_blocks(readme: str) -> list[str]:
    return re.findall(r"```[a-zA-Z0-9]*\n(.*?)```", readme, re.S)


def _is_solve_script(path: Path, blocks: list[str]) -> bool:
    """文件是否题解脚本：前 3 行非注释代码中 ≥2 行出现在 README 代码块里。
    （题面自带 .py 的反例靠 given-links 白名单优先保住——见 ingest 主循环。）"""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    lines = [ln.strip() for ln in text.splitlines()
             if ln.strip() and not ln.strip().startswith(("#", "//"))][:3]
    if not lines:
        return False
    blob = "\n".join(blocks)
    hits = sum(1 for ln in lines if ln[:60] and ln[:60] in blob)
    return hits >= 2


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]


def _points(info: str) -> int:
    m = re.search(r"Points:\s*(\d+)", info)
    return int(m.group(1)) if m else 0


def ingest(src: Path, dry: bool = False, year: str = "21", append: bool = False) -> list[dict]:
    rows = []
    for cat_dir in sorted(p for p in src.iterdir() if p.is_dir()):
        cat = cat_dir.name
        for ch_dir in sorted(p for p in cat_dir.iterdir() if p.is_dir()):
            readme_p = ch_dir / "README.md"
            if not readme_p.exists():
                continue
            readme = readme_p.read_text(encoding="utf-8", errors="ignore")
            secs = _sections(readme)
            flag = _extract_flag(readme)
            desc = secs.get("Challenge Description", "").strip()
            hints_raw = secs.get("Hints", "")
            hints = [re.sub(r"\[(.+?)\]\(.*?\)", r"\1", ln.lstrip(" -)*0123456789").strip())
                     for ln in hints_raw.splitlines() if ln.strip()]
            hints = [h for h in hints if h][:4]
            blocks = _code_blocks(readme)
            cid = f"pico{year}-{_slug(cat)}-{_slug(ch_dir.name)}"
            # 玩家视角判定：Description/Hints 里链接的文件 = 题目附件（必留）；
            # 只在 Solution 叙事里出现且内容撞代码块的 .py/.sh = 解题产物（剔除）
            player_facing = desc + "\n" + hints_raw
            given = set(re.findall(r"\]\(\./?([^)/]+)\)", player_facing))
            files, skipped_solve = [], []
            for f in sorted(ch_dir.iterdir()):
                if f.name == "README.md" or f.is_dir():
                    continue
                if f.name not in given and f.suffix in (".py", ".sh") and _is_solve_script(f, blocks):
                    skipped_solve.append(f.name)
                    continue
                files.append(f.name)
            # 离线可解启发：描述要求连服务(nc)时，服务已死——只有当附件里有非图片的
            # 数据文件（txt/py 输出等）才可能离线推导；纯图片/无附件的 nc 题跳过
            needs_live = bool(re.search(r"\bnc\s+\S+|connect (?:to|with)", desc, re.I))
            data_files = [f for f in files if not f.lower().endswith((".jpg", ".jpeg", ".png", ".gif"))]
            offline = (not needs_live and bool(files)) or (needs_live and bool(data_files))
            rows.append({
                "id": cid, "category": cat, "challenge": ch_dir.name,
                "points": _points(secs.get("Challenge Information", "")),
                "flag": flag, "desc": desc[:220], "hints": hints,
                "files": files, "skipped_solve_scripts": skipped_solve,
                "offline": offline,
            })
            if not dry and flag and files:
                dest = SERVE_ROOT / cid
                if dest.exists():
                    shutil.rmtree(dest)
                dest.mkdir(parents=True)
                for name in files:
                    shutil.copy2(ch_dir / name, dest / name)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(SRC))
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--year", default="21", help="cid 年份前缀（21/18…）")
    ap.add_argument("--append", action="store_true",
                    help="追加进现有 spec（按 类别+题名 去重——同年镜像仓常互相覆盖）")
    args = ap.parse_args()
    rows = ingest(Path(args.src), dry=args.dry, year=args.year)
    ok = [r for r in rows if r["flag"]]
    offline = [r for r in ok if r["offline"] and r["files"]]
    print(f"共 {len(rows)} 题 | 有flag {len(ok)} | 离线可解(有工件+非服务题) {len(offline)}")
    if not args.dry:
        spec = [{"id": r["id"], "category": r["category"], "points": r["points"],
                 "url": f"http://127.0.0.1:8901/{r['id']}/",
                 "sandbox_url": f"http://172.17.0.1:8901/{r['id']}/",
                 "flag": r["flag"], "desc": r["desc"], "hints": r["hints"]}
                for r in rows if r["flag"] and r["offline"] and r["files"]]
        if args.append and SPEC.exists():
            existing = json.loads(SPEC.read_text(encoding="utf-8"))
            def _key(t):  # 同题跨镜像仓：类别+题名 归一
                return (t.get("category", ""), t["id"].split("-", 2)[-1])
            have = {_key(t) for t in existing}
            spec = existing + [t for t in spec if _key(t) not in have]
        SPEC.parent.mkdir(parents=True, exist_ok=True)
        SPEC.write_text(json.dumps(spec, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"spec {'追加后' if args.append else '写入'} {SPEC}（{len(spec)} 题）")


if __name__ == "__main__":
    main()
