"""数据工厂 v1 单测：pico 摄取（flag/hints/玩家视角文件过滤）+ adapter + 轨迹归档纯逻辑。"""
import json

import pytest


def test_ingest_flag_and_hints(tmp_path):
    from benchmark.pico_ingest import ingest
    src = tmp_path / "Cryptography"
    ch = src / "Test Challenge"
    ch.mkdir(parents=True)
    (ch / "README.md").write_text(
        "# Test\n\n## Challenge Description\n\nDecrypt the file [data.txt](./data.txt).\n\n"
        "## Challenge Information\n\nPoints: 90\n\n## Hints\n\n1) Try ROT13\n\n"
        "## Solution\n\n```python\nimport owiener\nc = 123\n```\n\nThe flag is picoCTF{t3st_fl4g}.\n",
        encoding="utf-8")
    (ch / "data.txt").write_text("ciphertext", encoding="utf-8")
    (ch / "solve.py").write_text("import owiener\nc = 123\nprint('x')\n", encoding="utf-8")
    rows = ingest(src.parent, dry=True)
    assert len(rows) == 1
    r = rows[0]
    assert r["flag"] == "picoCTF{t3st_fl4g}"
    assert r["points"] == 90
    assert any("ROT13" in h for h in r["hints"])
    # 玩家视角：data.txt 是题目附件保留；solve.py 内容撞 README 代码块 → 剔
    assert "data.txt" in r["files"]
    assert "solve.py" in r["skipped_solve_scripts"]
    assert r["offline"] is True


def test_ingest_nc_challenge_without_data_skipped(tmp_path):
    from benchmark.pico_ingest import ingest
    src = tmp_path / "General Skills"
    ch = src / "Nice Netcat"
    ch.mkdir(parents=True)
    (ch / "README.md").write_text(
        "# N\n\n## Challenge Description\n\nConnect with nc mercury.picoctf.net 1.\n\n"
        "## Solution\n\nflag picoCTF{nc_nc}\n", encoding="utf-8")
    rows = ingest(src.parent, dry=True)
    assert rows[0]["offline"] is False  # 服务已死且无数据文件 → 不工件化


def test_pico_adapter_prompt_has_hints_and_no_flag_leak():
    from benchmark.adapters import get_adapter
    a = get_adapter("picoctf")
    tgt = {"cid": "pico21-x", "url": "http://127.0.0.1:8901/pico21-x/",
           "sandbox_url": "http://127.0.0.1:8901/pico21-x/", "desc": "d",
           "flag": "picoCTF{s3cr3t_v4lu3}", "hints": ["Try ROT13"]}
    txt = a.objective(tgt)
    assert "Try ROT13" in txt
    assert "submit_finding" in txt
    assert "picoCTF{s3cr3t_v4lu3}" not in txt  # 真值绝不进 prompt


def test_manifest_roundtrip(tmp_path, monkeypatch):
    from benchmark import factory
    monkeypatch.setattr(factory, "FACTORY_DIR", tmp_path)
    monkeypatch.setattr(factory, "MANIFEST", tmp_path / "manifest.jsonl")
    factory._append_manifest({"id": "a", "solved": True})
    factory._append_manifest({"id": "b", "solved": False})
    m = factory._load_manifest()
    assert m["a"]["solved"] is True and m["b"]["solved"] is False
