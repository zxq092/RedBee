"""SFT 导出器单测：格式清洗/去重/过滤。"""
import json

from benchmark.sft_export import load_trajectories, to_sft_record


def _traj(cid, msgs, category="Cryptography"):
    return {"task_id": "t1", "module": "objective", "turns": 5, "tool_calls": 7,
            "messages": msgs, "factory": {"cid": cid, "category": category,
            "flag": "picoCTF{x}", "bench": "picoctf"}}


def test_to_sft_record_cleans_roles(tmp_path):
    msgs = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "u"},
        {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "type": "function",
            "function": {"name": "bash", "arguments": "{\"cmd\":\"ls\"}"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "out"},
        {"role": "tool", "content": "no-id"},          # 缺 tool_call_id → 丢
        {"role": "weird", "content": "x"},              # 非法角色 → 丢
    ]
    rec = to_sft_record(_traj("a", msgs))
    assert len(rec["messages"]) == 4
    assert rec["meta"]["cid"] == "a" and rec["meta"]["tool_calls"] == 7


def test_load_dedup_by_mtime(tmp_path):
    old = tmp_path / "x.json"
    old.write_text(json.dumps(_traj("x", [{"role": "user", "content": "old"}])))
    import os, time
    os.utime(old, (time.time() - 100, time.time() - 100))
    new = tmp_path / "x.json"  # 同名覆盖写新
    new.write_text(json.dumps(_traj("x", [{"role": "user", "content": "new"}])))
    # 再造一个 factory.cid 相同但文件名不同的
    (tmp_path / "y.json").write_text(json.dumps(_traj("x", [{"role": "user", "content": "y"}])))
    trajs = load_trajectories(tmp_path)
    assert list(trajs) == ["x"]
    assert trajs["x"]["messages"][0]["content"] == "new"


def test_min_msgs_filter_via_cli(tmp_path, capsys):
    from benchmark.sft_export import main
    d = tmp_path / "solved"
    d.mkdir()
    (d / "thin.json").write_text(json.dumps(_traj("thin", [{"role": "user", "content": "u"}])))
    (d / "fat.json").write_text(json.dumps(_traj("fat", [
        {"role": "system", "content": "s"}] + [{"role": "user", "content": f"u{i}"} for i in range(12)])))
    out = tmp_path / "sft.jsonl"
    import sys
    sys.argv = ["sft_export", "--solved-dir", str(d), "--out", str(out), "--min-msgs", "10"]
    rc = main()
    assert rc == 0
    lines = [json.loads(l) for l in out.read_text().splitlines()]
    assert len(lines) == 1 and lines[0]["meta"]["cid"] == "fat"
