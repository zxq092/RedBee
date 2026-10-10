#!/usr/bin/env python3
"""RedBee CLI: thin operator client for the PI gateway.

All mutating operations go through the same HTTP API used by the Web UI, so
tasks created from CLI appear in the same session/task/board/log data plane.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from typing import Any, Dict, Iterator, List, Optional

import httpx

DEFAULT_URL = os.environ.get("REDBEE_URL", "http://127.0.0.1:8100")
TERMINAL_TASKS = {"done", "cancelled", "runtime_error", "extraction_error", "interrupted"}


class ApiError(RuntimeError):
    pass


def default_operator() -> str:
    return os.environ.get("REDBEE_OPERATOR", "") or getpass.getuser()


def parse_params(pairs: Optional[List[str]]) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(f"invalid --param {pair!r}, expected key=value")
        key, value = pair.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise SystemExit(f"invalid --param {pair!r}, empty key")
        if value.lower() in {"true", "false"}:
            params[key] = value.lower() == "true"
            continue
        try:
            params[key] = int(value)
            continue
        except ValueError:
            pass
        try:
            params[key] = float(value)
            continue
        except ValueError:
            pass
        params[key] = value
    return params


def build_task_body(
    task: str,
    target: str,
    session_id: str,
    target_id: str = "",
    agents: Optional[List[str]] = None,
    params: Optional[Dict[str, Any]] = None,
    source: str = "cli",
    operator: str = "",
) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "task": task,
        "target": target,
        "session_id": session_id,
        "source": source or "cli",
        "operator": operator or default_operator(),
    }
    if target_id:
        body["target_id"] = target_id
    if agents:
        body["agents"] = agents
    if params:
        body["params"] = params
    return body


class RedbeeClient:
    def __init__(self, base_url: str, session_token: str = "", timeout: float = 20.0, transport=None):
        self.base = base_url.rstrip("/")
        headers = {}
        if session_token:
            headers["Authorization"] = f"Bearer {session_token}"
        self.client = httpx.Client(headers=headers, timeout=timeout, transport=transport)

    def _raise(self, resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            try:
                data = resp.json()
            except Exception:
                data = {"error": resp.text[:500]}
            raise ApiError(f"HTTP {resp.status_code}: {json.dumps(data, ensure_ascii=False)}")

    def get(self, path: str) -> Any:
        resp = self.client.get(self.base + path)
        self._raise(resp)
        return resp.json()

    def post(self, path: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        resp = self.client.post(self.base + path, json=payload or {})
        self._raise(resp)
        return resp.json()

    def get_text(self, path: str) -> str:
        resp = self.client.get(self.base + path)
        self._raise(resp)
        return resp.text

    def iter_sse(self, path: str) -> Iterator[Dict[str, Any]]:
        with self.client.stream("GET", self.base + path) as resp:
            if resp.status_code >= 400:
                body = resp.read().decode("utf-8", "replace")
                raise ApiError(f"HTTP {resp.status_code}: {body[:500]}")
            for line in resp.iter_lines():
                if not line or not line.startswith("data:"):
                    continue
                raw = line[5:].strip()
                if not raw:
                    continue
                try:
                    yield json.loads(raw)
                except json.JSONDecodeError:
                    continue

    def close(self) -> None:
        self.client.close()


def create_client(args: argparse.Namespace) -> RedbeeClient:
    base = args.url or os.environ.get("REDBEE_URL", DEFAULT_URL)
    token = args.token or os.environ.get("REDBEE_SESSION_TOKEN", "")
    if not token:
        bootstrap = (
            args.web_token
            or os.environ.get("REDBEE_WEB_TOKEN", "")
            or os.environ.get("PIMETA_WEB_TOKEN", "")
        )
        if bootstrap:
            try:
                with httpx.Client(timeout=10) as tmp:
                    resp = tmp.post(base.rstrip("/") + "/api/login", json={"token": bootstrap})
                    if resp.status_code == 200:
                        token = resp.json().get("session_token", "")
            except httpx.HTTPError:
                token = ""
    return RedbeeClient(base, token, timeout=args.timeout)


def print_result(data: Any, as_json: bool, human=None) -> None:
    if as_json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    if human is not None:
        human(data)


def _fmt_findings_brief(findings: List[Dict[str, Any]], full: bool = False) -> None:
    if not findings:
        print("no findings")
        return
    for f in findings:
        title = str(f.get("title", ""))
        loc = f.get("location", "")
        print(f"- [{f.get('severity','')}/{f.get('status','')}] #{f.get('id','')} {title} {loc}".rstrip())
        if full:
            poc = str(f.get("poc", "")).strip()
            evidence = str(f.get("evidence", "")).strip()
            if poc:
                print(f"  poc: {poc[:1200]}")
            if evidence:
                print(f"  evidence: {evidence[:1200]}")


def human_status(data: Dict[str, Any]) -> None:
    board = data.get("board") or {}
    meta = data.get("meta") or {}
    findings = board.get("findings") or []
    print(f"task: {data.get('task_id','')}")
    print(f"status: {board.get('status') or meta.get('status','')}")
    if meta.get("source"):
        print(f"source: {meta.get('source')}")
    if meta.get("operator"):
        print(f"operator: {meta.get('operator')}")
    print(f"target: {meta.get('target') or data.get('target') or '-'}")
    if meta.get("mode"):
        print(f"mode: {meta.get('mode')}")
    print(f"findings: {len(findings)}")
    if meta.get("updated_at"):
        print(f"updated_at: {meta.get('updated_at')}")
    if meta.get("runtime_error_summary"):
        print(f"error: {meta.get('runtime_error_summary')}")


def _summarize_live(live: Dict[str, Any]) -> str:
    slots = []
    for _, slot in (live.get("slots") or {}).items():
        label = slot.get("label") or slot.get("agent") or "?"
        state = slot.get("state") or ""
        phase = slot.get("phase") or ""
        tool = slot.get("tool") or ""
        msg = str(slot.get("last_message") or "")
        bits = [x for x in (state, phase, tool, msg[:100]) if x]
        slots.append(f"[{label}] {' '.join(bits)}")
    queue = live.get("queue") or []
    verify = live.get("verify_q") or []
    tail = []
    if queue:
        tail.append(f"queue={len(queue)}")
    if verify:
        tail.append(f"verify={len(verify)}")
    return " | ".join(slots + tail) or "idle"


def cmd_task_run(args: argparse.Namespace, client: RedbeeClient) -> None:
    session_id = args.session_id
    if not session_id:
        created = client.post("/api/sessions", {"title": f"CLI: {args.task[:32]}"})
        session_id = created.get("id", "")
        if not session_id:
            raise ApiError("failed to create session")
    body = build_task_body(
        task=args.task,
        target=args.target,
        session_id=session_id,
        target_id=args.target_id or "",
        agents=args.agent or None,
        params=parse_params(args.param),
        source="cli",
        operator=args.operator or default_operator(),
    )
    data = client.post("/api/task", body)
    print_result(data, args.json, lambda d: print(
        f"task_id: {d.get('task_id','')}\n"
        f"session_id: {session_id}\n"
        f"status: {d.get('status','')}\n"
        f"mode: {d.get('mode','')}\n"
        f"source: cli"
    ))


def cmd_task_status(args: argparse.Namespace, client: RedbeeClient) -> None:
    meta = client.get(f"/api/task/{args.task_id}/meta")
    board = client.get(f"/api/task/{args.task_id}/board")
    data = {"task_id": args.task_id, "meta": meta, "board": board}
    print_result(data, args.json, human_status)


def cmd_task_watch(args: argparse.Namespace, client: RedbeeClient) -> None:
    try:
        for event in client.iter_sse(f"/api/task/{args.task_id}/stream"):
            etype = event.get("type")
            if etype == "live":
                if args.json:
                    print(json.dumps(event, ensure_ascii=False))
                else:
                    print(_summarize_live(event))
            elif etype == "done":
                if not args.json:
                    print(f"done: {event.get('reason','')}")
                else:
                    print(json.dumps(event, ensure_ascii=False))
                return
        return
    except ApiError as exc:
        if "404" not in str(exc):
            raise
    meta = client.get(f"/api/task/{args.task_id}/meta")
    while True:
        board = client.get(f"/api/task/{args.task_id}/board")
        status = board.get("status") or meta.get("status")
        if args.json:
            print(json.dumps({"status": status, "board": board}, ensure_ascii=False))
        else:
            print(f"status: {status}")
        if status in TERMINAL_TASKS:
            return
        time.sleep(args.interval)


def cmd_task_board(args: argparse.Namespace, client: RedbeeClient) -> None:
    data = client.get(f"/api/task/{args.task_id}/board")
    print_result(data, args.json, lambda d: _fmt_findings_brief(d.get("findings") or []))


def cmd_task_findings(args: argparse.Namespace, client: RedbeeClient) -> None:
    data = client.get(f"/api/task/{args.task_id}/board")
    findings = (data.get("findings") or [])[: args.limit]
    print_result(findings, args.json, lambda fs: _fmt_findings_brief(fs, full=args.full))


def cmd_task_report(args: argparse.Namespace, client: RedbeeClient) -> None:
    data = client.get(f"/api/task/{args.task_id}/report")
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    report_md = data.get("report_md", "")
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(report_md)
        print(f"saved: {args.save}")
    else:
        print(report_md)


def cmd_task_log(args: argparse.Namespace, client: RedbeeClient) -> None:
    data = client.get(f"/api/task/{args.task_id}/log")
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    lines = []
    for row in data.get("lines") or []:
        ts = str(row.get("ts", ""))
        short_ts = ts[11:19] if len(ts) >= 19 else ts
        module = f"[{row.get('module')}] " if row.get("module") else ""
        lines.append(f"{short_ts} {module}{row.get('kind','')}: {row.get('detail','')}")
    text = "\n".join(lines)
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"saved: {args.save}")
    else:
        print(text)


def cmd_task_attack_chain(args: argparse.Namespace, client: RedbeeClient) -> None:
    data = client.get(f"/api/task/{args.task_id}/attack-chain")
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    if data.get("status") != "ok":
        print(f"status: {data.get('status','building')}")
        return
    print(f"summary: {data.get('summary','')}")
    print(f"risk_score: {data.get('risk_score','')}")
    for node in data.get("nodes") or []:
        print(f"- [{node.get('phase','')}] {node.get('title','')}: {node.get('detail','')}")
    edges = data.get("edges") or []
    if edges:
        print("edges: " + ", ".join(f"{e.get('from')}->{e.get('to')} ({e.get('label','')})" for e in edges))


def cmd_task_cancel(args: argparse.Namespace, client: RedbeeClient) -> None:
    data = client.post(f"/api/task/{args.task_id}/cancel", {})
    print_result(data, args.json, lambda d: print(f"cancelled: {d.get('cancelled', 0)}"))


def cmd_finding_detail(args: argparse.Namespace, client: RedbeeClient) -> None:
    data = client.get(f"/api/finding/{args.finding_id}")
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    print(f"finding: #{data.get('id','')} [{data.get('severity','')}/{data.get('status','')}]")
    print(f"title: {data.get('title','')}")
    print(f"location: {data.get('location','')}")
    if data.get("poc"):
        print(f"poc:\n{data.get('poc')}")
    if data.get("evidence"):
        print(f"evidence:\n{data.get('evidence')}")
    if data.get("retest_verdict"):
        print(f"retest: {data.get('retest_verdict')}")


def cmd_finding_retest(args: argparse.Namespace, client: RedbeeClient) -> None:
    payload = {"source": "cli", "operator": args.operator or default_operator()}
    if args.session_id:
        payload["session_id"] = args.session_id
    data = client.post(f"/api/finding/{args.finding_id}/retest", payload)
    print_result(data, args.json, lambda d: print(f"retest_task_id: {d.get('retest_task_id','')}"))


def cmd_tasks_list(args: argparse.Namespace, client: RedbeeClient) -> None:
    path = "/api/tasks"
    if args.status:
        path += f"?status={args.status}"
    data = client.get(path)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    if not data:
        print("no tasks")
        return
    for t in data:
        source = f" source={t['source']}" if t.get("source") else ""
        print(
            f"{t.get('task_id','')} {t.get('status','')} "
            f"findings={t.get('findings',0)} target={t.get('target') or t.get('target_id') or '-'}"
            f"{source}"
        )


def cmd_sessions_list(args: argparse.Namespace, client: RedbeeClient) -> None:
    data = client.get("/api/sessions")
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    for s in data:
        print(f"{s.get('id','')} {s.get('title','')} {s.get('created_at','')}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redbee", description="RedBee gateway CLI")
    parser.add_argument("--url", default="", help=f"gateway base URL (default {DEFAULT_URL})")
    parser.add_argument("--token", default="", help="gateway session token")
    parser.add_argument("--web-token", default="", help="bootstrap PIMETA_WEB_TOKEN for /api/login")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout seconds")
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    task = sub.add_parser("task", help="task operations")
    task_sub = task.add_subparsers(dest="task_command", required=True)

    p = task_sub.add_parser("run", help="dispatch a new task")
    p.add_argument("--task", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--session-id", default="")
    p.add_argument("--target-id", default="")
    p.add_argument("--agent", action="append")
    p.add_argument("--param", action="append", help="key=value task param, repeatable")
    p.add_argument("--operator", default="")
    p.set_defaults(func=cmd_task_run)

    p = task_sub.add_parser("status", help="task status from DB + board")
    p.add_argument("task_id")
    p.set_defaults(func=cmd_task_status)

    p = task_sub.add_parser("watch", help="stream task progress")
    p.add_argument("task_id")
    p.add_argument("--interval", type=float, default=3.0)
    p.set_defaults(func=cmd_task_watch)

    p = task_sub.add_parser("board", help="list findings board")
    p.add_argument("task_id")
    p.set_defaults(func=cmd_task_board)

    p = task_sub.add_parser("findings", help="list findings")
    p.add_argument("task_id")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--full", action="store_true")
    p.set_defaults(func=cmd_task_findings)

    p = task_sub.add_parser("report", help="show/save markdown report")
    p.add_argument("task_id")
    p.add_argument("--save", default="")
    p.set_defaults(func=cmd_task_report)

    p = task_sub.add_parser("log", help="show/save task execution log")
    p.add_argument("task_id")
    p.add_argument("--save", default="")
    p.set_defaults(func=cmd_task_log)

    p = task_sub.add_parser("attack-chain", help="show attack chain")
    p.add_argument("task_id")
    p.set_defaults(func=cmd_task_attack_chain)

    p = task_sub.add_parser("cancel", help="cancel task")
    p.add_argument("task_id")
    p.set_defaults(func=cmd_task_cancel)

    finding = sub.add_parser("finding", help="finding operations")
    finding_sub = finding.add_subparsers(dest="finding_command", required=True)
    p = finding_sub.add_parser("detail")
    p.add_argument("finding_id", type=int)
    p.set_defaults(func=cmd_finding_detail)
    p = finding_sub.add_parser("retest")
    p.add_argument("finding_id", type=int)
    p.add_argument("--session-id", default="")
    p.add_argument("--operator", default="")
    p.set_defaults(func=cmd_finding_retest)

    p = sub.add_parser("tasks", help="list tasks")
    p.add_argument("--status", default="")
    p.set_defaults(func=cmd_tasks_list)

    p = sub.add_parser("sessions", help="list sessions")
    p.set_defaults(func=cmd_sessions_list)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    client = create_client(args)
    try:
        args.func(args, client)
        return 0
    except ApiError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(f"gateway request failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
