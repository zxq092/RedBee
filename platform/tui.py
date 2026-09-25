#!/usr/bin/env python3
"""RedBee TUI — 终端实时监视器（与 Web 同视图：状态行 + 执行卡 + 漏洞板摘要）。

数据源全部复用 PI 网关现有 API（零后端改动）：
  GET  /api/tasks                 任务列表（含 running + findings 计数）
  GET  /api/task/{id}/meta        任务元数据（created_at/updated_at/status）
  GET  /api/task/{id}/board       漏洞板（findings + status，终态判定真源）
  GET  /api/task/{id}/stream      SSE 实时流（type=live 快照 / type=done 结束）
  POST /api/task/{id}/cancel      停止任务

用法（CWD=platform）：
  python3 tui.py [--url http://127.0.0.1:8100] [--token <web-token>]

键位：
  列表: ↑/↓ 选择 · Enter 打开 · r 刷新 · q 退出
  任务: b/Esc/q 返回列表 · s 停止任务(y 确认) · r 立即刷新
"""
import argparse
import json
import os
import select
import sys
import termios
import threading
import time
import tty

import httpx
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

TERMINAL = {"done", "cancelled", "runtime_error", "extraction_error", "interrupted"}
PHASES = ["pre-recon", "recon", "root-decide", "exploit", "report"]
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {"critical": "red", "high": "orange3", "medium": "yellow",
             "low": "blue", "info": "grey58"}
STATUS_COLOR = {"running": "green", "done": "blue", "cancelled": "yellow",
                "interrupted": "magenta", "runtime_error": "red", "extraction_error": "red"}
STATUS_ZH = {"running": "执行中", "done": "完成", "cancelled": "已停止",
             "interrupted": "中断", "runtime_error": "失败", "extraction_error": "失败"}
# opencode 式 4 方块左→右波浪（8 帧循环；●=亮 ○=暗）
ANIM_FRAMES = [
    "●○○○", "●●○○", "●●●○", "●●●●",
    "○●●●", "○○●●", "○○○●", "○○○○",
]


def _read_key(timeout: float = 0.1):
    """非阻塞读一个键（cbreak 模式）；超时返回 None。

    ⚠️ 必须用 os.read 裸 fd：sys.stdin 带缓冲，read(1) 会把同包多字节
    （如 ↓=\\x1b[B 整包）吸入 Python 缓冲区，后续 select(fd) 只看到空 fd，
    残留字节永远读不到 → 按键错乱。"""
    fd = sys.stdin.fileno()
    if not sys.stdin.isatty():
        time.sleep(timeout)
        return None
    r, _, _ = select.select([fd], [], [], timeout)
    if not r:
        return None
    c = os.read(fd, 1)
    if c == b"\x1b":
        r2, _, _ = select.select([fd], [], [], 0.02)
        if r2:
            c2 = os.read(fd, 1)
            if c2 == b"[":
                r3, _, _ = select.select([fd], [], [], 0.02)
                if r3:
                    c3 = os.read(fd, 1)
                    return {"A": "up", "B": "down", "C": "right", "D": "left"}.get(c3.decode(), "esc")
        return "esc"
    if c in (b"\r", b"\n"):
        return "enter"
    if c == b"\x03":
        return "ctrl_c"
    return c.decode("utf-8", "replace")


def _fmt_dur(created_at: str, end: str | None) -> str:
    """created_at/updated_at(ISO) → '12m34s'；失败返回 ''。"""
    def _p(s):
        try:
            return time.mktime(time.strptime(s[:19], "%Y-%m-%dT%H:%M:%S"))
        except Exception:
            return None
    s = _p(created_at)
    if not s:
        return ""
    e = _p(end) if end else time.time()
    d = max(0, int((e or time.time()) - s))
    if d < 60:
        return f"{d}s"
    if d < 3600:
        return f"{d // 60}m{d % 60:02d}s"
    return f"{d // 3600}h{(d % 3600) // 60:02d}m"


def _clean_msg(s: str) -> str:
    import re
    return re.sub(r"^\[[^\]]*\]\s*", "", s or "")


class Api:
    def __init__(self, base: str, token: str | None = None):
        self.base = base.rstrip("/")
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        self.client = httpx.Client(headers=headers, timeout=httpx.Timeout(8))

    def get(self, path: str):
        r = self.client.get(self.base + path)
        r.raise_for_status()
        return r.json()

    def post(self, path: str):
        r = self.client.post(self.base + path)
        r.raise_for_status()
        return r.json()


class TaskView:
    """单任务实时状态。SSE 线程消费 /stream；board 由主循环 5s 轮询（终态真源）。"""

    def __init__(self, api: Api, task_id: str):
        self.api = api
        self.task_id = task_id
        self.lock = threading.Lock()
        self.live: dict = {}
        self.findings: list = []
        self.status = "running"
        self.meta: dict = {}
        self.mods: dict = {}        # module -> {state, msgs, last}（事件累积，含已结束模块）
        self.phase = ""
        self.last_activity = time.time()
        self.opened_at = time.time()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sse, daemon=True)
        self._thread.start()

    def _sse(self):
        # ⚠️ httpx.Client 非线程安全：SSE 线程必须用独立 client（与主线程
        # 的 board/meta GET 并发），共用会抢连接池导致主循环阻塞。
        try:
            client = httpx.Client(
                headers=dict(self.api.client.headers),
                timeout=httpx.Timeout(30, read=90))
            try:
                with client.stream(
                        "GET", f"/api/task/{self.task_id}/stream",
                        headers={"Accept": "text/event-stream"}) as r:
                    if r.status_code != 200:
                        return
                    for line in r.iter_lines():
                        if self._stop.is_set():
                            return
                        if not line.startswith("data: "):
                            continue
                        try:
                            d = json.loads(line[6:])
                        except Exception:
                            continue
                        with self.lock:
                            t = d.get("type")
                            if t == "live":
                                self.live = d
                                self.last_activity = time.time()
                                self._apply_slots(d)
                            elif t == "done":
                                self.last_activity = time.time()
            finally:
                client.close()
        except Exception:
            pass  # SSE 断/404（任务已结算）→ 靠 board 轮询兜底

    def _apply_slots(self, d: dict):
        for s in (d.get("slots") or {}).values():
            lt = s.get("last_type") or ""
            name = s.get("module") or (s.get("label") or "main")
            m = self.mods.setdefault(name, {"state": "run", "msgs": 0, "last": ""})
            if s.get("msg_count"):
                m["msgs"] = s["msg_count"]
            if s.get("last_message"):
                m["last"] = s["last_message"]
            if s.get("phase"):
                self.phase = s["phase"]
            if lt == "module_start":
                m["state"] = "run"
            elif lt == "module_done":
                m["state"] = "done"
            elif lt == "module_fail":
                m["state"] = "fail"
            elif s.get("state") == "done" and lt not in ("module_done", "module_fail"):
                pass  # 保留已累积状态

    def refresh(self):
        """主循环调用：meta + board 快照（终态判定真源）。"""
        try:
            self.meta = self.api.get(f"/api/task/{self.task_id}/meta")
        except Exception:
            pass
        try:
            b = self.api.get(f"/api/task/{self.task_id}/board")
            with self.lock:
                self.findings = b.get("findings") or []
                if b.get("status"):
                    self.status = b["status"]
        except Exception:
            pass

    def snapshot(self):
        with self.lock:
            return {
                "live": self.live, "findings": list(self.findings), "status": self.status,
                "meta": dict(self.meta), "mods": {k: dict(v) for k, v in self.mods.items()},
                "phase": self.phase, "last_activity": self.last_activity,
                "opened_at": self.opened_at,
            }

    def close(self):
        self._stop.set()


def _sev_bar(findings: list) -> Text:
    valid = [f for f in findings if str(f.get("status", "found")).lower() != "false_positive"]
    sev = {k: 0 for k in SEV_ORDER}
    for f in valid:
        s = str(f.get("severity", "info")).lower()
        if s in sev:
            sev[s] += 1
    t = Text()
    for k in SEV_ORDER:
        if sev[k]:
            t.append("█" * sev[k], style=SEV_COLOR[k])
    if not any(sev.values()):
        return Text("（无有效发现）", style="grey58")
    t.append("   ", style="grey58")
    for k in SEV_ORDER:
        if sev[k]:
            t.append(f"{k} {sev[k]}  ", style=SEV_COLOR[k])
    t.append(f"共 {len(valid)} 条", style="grey58")
    return t


def _digest(findings: list) -> Text:
    """漏洞摘要（与 Web 同逻辑）：总览行 + 每类漏洞一行（组内最高严重度着色 + 最多 2 代表标题）。"""
    valid = [f for f in findings if str(f.get("status", "found")).lower() != "false_positive"]
    if not valid:
        return Text("")
    t = Text()
    sev_tot = {k: 0 for k in SEV_ORDER}
    for f in valid:
        s = str(f.get("severity", "info")).lower()
        if s in sev_tot:
            sev_tot[s] += 1
    parts = [f"{k} {sev_tot[k]}" for k in SEV_ORDER if sev_tot[k]]
    line = f"{len(valid)} 条有效发现"
    if parts:
        line += "（" + " / ".join(parts) + "）"
    confirmed = sum(1 for f in valid if str(f.get("status", "")).lower() == "confirmed")
    if confirmed:
        line += f" · confirmed {confirmed}"
    t.append(line + "\n", style="bold")
    rank = {k: i for i, k in enumerate(SEV_ORDER)}
    groups: dict = {}
    for f in valid:
        groups.setdefault(f.get("vuln_class") or "未分类", []).append(f)
    glist = sorted(groups.items(), key=lambda kv: (
        min(rank.get(str(x.get("severity", "info")).lower(), 9) for x in kv[1]),
        -len(kv[1])))
    for k, arr in glist[:8]:
        top = sorted(arr, key=lambda x: rank.get(str(x.get("severity", "info")).lower(), 9))[0]
        sev_name = str(top.get("severity", "info")).lower()
        titles = list(dict.fromkeys(f.get("title") or "" for f in arr))[:2]
        t.append("■ ", style=SEV_COLOR.get(sev_name, "grey58"))
        t.append(f"{k}（{sev_name}×{len(arr)}）", style="bold")
        if titles:
            t.append("  " + "；".join(titles), style="grey62")
        t.append("\n")
    if len(glist) > 8:
        t.append(f"…另 {len(glist) - 8} 类见下方列表\n", style="grey58")
    return t[:-1] if t.plain.endswith("\n") else t


class RedBeeTUI:
    BOARD_EVERY = 5.0
    LIST_EVERY = 5.0

    def __init__(self, api: Api):
        self.api = api
        self.console = Console()
        self.tasks: list = []
        self.sel = 0
        self.cur: TaskView | None = None
        self._last_board = 0.0
        self._last_list = 0.0
        self._confirm_stop: str | None = None
        self._frame = 0
        self._last_tick = time.time()
        self.error = ""
        self.exit_flag = False

    # ---------- 数据 ----------
    def refresh_tasks(self):
        try:
            self.tasks = self.api.get("/api/tasks")
        except Exception as e:
            self.error = f"网关不可达 {self.api.base}: {e}"
            return
        if self.sel >= len(self.tasks):
            self.sel = max(0, len(self.tasks) - 1)

    def open_task(self, task_id: str):
        tv = TaskView(self.api, task_id)
        tv.refresh()
        self.cur = tv
        self._last_board = time.time()

    def close_task(self):
        if self.cur:
            self.cur.close()
        self.cur = None
        self._confirm_stop = None
        self.refresh_tasks()

    # ---------- 渲染 ----------
    def render(self):
        if self.cur is None:
            return self._render_list()
        return self._render_task()

    def _anim(self, active: bool) -> Text:
        t = Text()
        if active:
            f = ANIM_FRAMES[self._frame % len(ANIM_FRAMES)]
            for i, ch in enumerate(f):
                t.append("■" if ch == "●" else "□",
                         style="green" if ch == "●" else "grey37")
                if i < 3:
                    t.append(" ")
        return t

    def _render_list(self):
        head = Text()
        head.append(" RedBee · 任务列表", style="bold cyan")
        head.append(f"   {self.api.base}", style="grey58")
        hint = Text(" ↑/↓ 选择 · Enter 打开 · r 刷新 · q 退出", style="grey58")
        body = [Panel(Group(head, Text("")), border_style="cyan", padding=(0, 1))]
        if self.error:
            body.append(Panel(Text(self.error, style="red"), border_style="red"))
        if not self.tasks:
            body.append(Panel(Text("暂无任务", style="grey58"), border_style="grey37"))
        else:
            tb = Table(box=None, pad_edge=False, expand=True)
            for col in ("状态", "task_id", "findings", "模块", "目标", "开始"):
                tb.add_column(col, overflow="fold")
            tb.add_column("session", overflow="fold")
            for i, t in enumerate(self.tasks[:60]):
                st = t.get("status", "?")
                row = [
                    Text(STATUS_ZH.get(st, st), style=STATUS_COLOR.get(st, "grey58")),
                    t.get("task_id", "")[:20],
                    str(t.get("findings", 0)),
                    f'{t.get("modules_done", 0)}/{t.get("modules_total", 0)}',
                    (t.get("target") or "")[:24],
                    (t.get("created_at") or "")[11:19],
                    (t.get("session_id") or "")[:10],
                ]
                style = "cyan " if i == self.sel else ""
                tb.add_row(*row, style=style)
            body.append(Panel(Group(hint, tb), border_style="grey37"))
        return Group(*body)

    def _render_task(self):
        tv = self.cur
        snap = tv.snapshot()
        st = snap["status"]
        running = st not in TERMINAL
        meta = snap["meta"]
        created = meta.get("created_at") or ""
        end = None if running else (meta.get("updated_at") or "")
        dur = _fmt_dur(created, end)

        # ---- 状态行（opencode 式方块动画 + 相位 + 时长 + 上次活动）----
        sl = Text()
        sl.append(" " + str(self._anim(running)) + "  ")
        if running:
            sl.append("执行中", style="bold green")
            ph = snap["phase"]
            if ph:
                sl.append(f" · {ph}", style="bold")
            if dur:
                sl.append(f" · 已运行 {dur}", style="grey62")
            idle = max(0, int(time.time() - snap["last_activity"]))
            if idle < 90:
                sl.append(f" · 上次活动 {idle}s 前", style="grey62")
            else:
                sl.append(f" · LLM 思考中… {idle // 60}min", style="yellow")
        else:
            sl.append(STATUS_ZH.get(st, st), style=f"bold {STATUS_COLOR.get(st, 'grey58')}")
            if dur:
                sl.append(f" · 用时 {dur}", style="grey62")
            if st == "cancelled":
                sl.append(" · 用户终止（保留部分成果）", style="grey58")
            elif st in ("runtime_error", "extraction_error"):
                code = meta.get("runtime_error_summary") or meta.get("extraction_error") or ""
                sl.append(f" · {code}", style="red")
        sl.append("   [s 停止 · b 返回]", style="grey37")
        if self._confirm_stop:
            sl.append("  确认停止该任务？[y 确认 / 其他取消]", style="bold red")

        body = [Panel(sl, border_style="green" if running else STATUS_COLOR.get(st, "grey37"),
                      padding=(0, 1))]

        # ---- 执行过程（相位步进 + 模块行）----
        stepper = Text()
        try:
            idx = PHASES.index(snap["phase"]) if snap["phase"] in PHASES else -1
        except ValueError:
            idx = -1
        done_n = sum(1 for m in snap["mods"].values() if m["state"] in ("done", "fail"))
        seen_n = len(snap["mods"])
        for i, p in enumerate(PHASES):
            if i:
                stepper.append(" › ", style="grey37")
            if running and idx >= 0 and i < idx:
                stepper.append(f"{p}✓", style="grey58")
            elif running and idx >= 0 and i == idx:
                extra = f" {done_n}/{seen_n}" if p == "exploit" and seen_n else ""
                stepper.append(p + extra, style="bold green")
            elif not running:
                stepper.append(f"{p}✓", style="grey58")
            else:
                stepper.append(p, style="grey37")

        mods_t = Table(box=None, pad_edge=False, expand=True, show_edge=False)
        mods_t.add_column("模块", width=14, overflow="fold")
        mods_t.add_column("状态", width=8)
        mods_t.add_column("msgs", width=6, justify="right")
        mods_t.add_column("最近动作", overflow="fold")
        for name, m in list(snap["mods"].items())[:20]:
            sc = {"run": "green", "done": "blue", "fail": "red"}.get(m["state"], "grey58")
            sz = {"run": "运行中", "done": "完成", "fail": "失败"}.get(m["state"], m["state"])
            mods_t.add_row(name[:14], Text(sz, style=sc), str(m.get("msgs", 0)),
                           _clean_msg(m.get("last", ""))[:80])
        if not snap["mods"]:
            mods_t.add_row("-", Text("等待派发…", style="grey58"), "", "")
        body.append(Panel(Group(stepper, mods_t), title="执行过程",
                          subtitle=tv.task_id[:24], border_style="grey37"))

        # ---- 漏洞板（摘要 + 分布条 + 明细）----
        findings = snap["findings"]
        digest = _digest(findings)
        parts = []
        if digest:
            parts.append(Panel(digest, title="漏洞摘要", border_style="blue", expand=True))
        parts.append(_sev_bar(findings))
        rows_t = Table(box=None, pad_edge=False, expand=True, show_edge=False)
        rows_t.add_column("sev", width=9)
        rows_t.add_column("标题", overflow="fold")
        rows_t.add_column("位置", width=28, overflow="fold", style="grey62")
        rows_t.add_column("状态", width=10)
        for f in sorted(findings, key=lambda x: (
                SEV_ORDER.index(str(x.get("severity", "info")).lower())
                if str(x.get("severity", "info")).lower() in SEV_ORDER else 9,
                x.get("id", 0))):
            sev = str(f.get("severity", "info")).lower()
            fp = str(f.get("status", "found")).lower() == "false_positive"
            stl = "grey58" if fp else "grey62"
            rows_t.add_row(
                Text(sev, style=f"bold {SEV_COLOR.get(sev, 'grey58')}{' strike' if fp else ''}"),
                Text((f.get("title") or "")[:70], style="strike grey58" if fp else ""),
                (f.get("location") or "")[:28],
                Text(f.get("status") or "found", style=stl))
        if not findings:
            rows_t.add_row("", Text("暂无发现", style="grey58"), "", "")
        valid_n = sum(1 for f in findings
                      if str(f.get("status", "found")).lower() != "false_positive")
        body.append(Panel(Group(*parts), title=f"🛡 漏洞板  {valid_n} 条",
                          border_style="grey37"))
        return Group(*body)

    # ---------- 主循环 ----------
    def run(self):
        if not sys.stdin.isatty():
            print("TUI 需要交互式终端（tty）", file=sys.stderr)
            sys.exit(1)
        self.refresh_tasks()
        old = termios.tcgetattr(sys.stdin)
        try:
            tty.setcbreak(sys.stdin.fileno())
            with Live(self.render(), console=self.console,
                      auto_refresh=False, screen=True) as live:
                while not self.exit_flag:
                    self.tick(live)
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
            if self.cur:
                self.cur.close()

    def tick(self, live: Live):
        now = time.time()
        if now - self._last_tick >= 0.25:
            self._frame += 1
            self._last_tick = now
        key = _read_key(0.1)
        if key == "ctrl_c":
            self.exit_flag = True
            return
        if self.cur is None:
            if key == "q":
                self.exit_flag = True
            elif key == "r":
                self.refresh_tasks()
                self._last_list = now
            elif key == "up" and self.tasks:
                self.sel = (self.sel - 1) % len(self.tasks)
            elif key == "down" and self.tasks:
                self.sel = (self.sel + 1) % len(self.tasks)
            elif key == "enter" and self.tasks:
                self.open_task(self.tasks[self.sel].get("task_id", ""))
            elif now - self._last_list >= self.LIST_EVERY:
                self.refresh_tasks()
                self._last_list = now
        else:
            if key in ("b", "esc", "q"):
                self.close_task()
            elif key == "s" and self.cur and self.cur.snapshot()["status"] not in TERMINAL:
                self._confirm_stop = self.cur.task_id
            elif self._confirm_stop:
                if key == "y":
                    try:
                        self.api.post(f"/api/task/{self._confirm_stop}/cancel")
                    except Exception as e:
                        self.error = f"停止失败: {e}"
                    self._confirm_stop = None
                    self.cur.refresh()
                else:
                    self._confirm_stop = None
            elif key == "r" or now - self._last_board >= self.BOARD_EVERY:
                self.cur.refresh()
                self._last_board = now
        # ⚠️ auto_refresh=False 下 update() 只换 renderable 不重绘，必须 refresh=True
        live.update(self.render(), refresh=True)


def main():
    ap = argparse.ArgumentParser(description="RedBee TUI — 终端实时监视器")
    ap.add_argument("--url", default=os.environ.get("PIMETA_URL", "http://127.0.0.1:8100"),
                    help="PI 网关地址（默认 $PIMETA_URL 或 http://127.0.0.1:8100）")
    ap.add_argument("--token", default=os.environ.get("PIMETA_WEB_TOKEN", ""),
                    help="Web token（启用鉴权的网关需要；GET 只读端点一般免鉴权）")
    args = ap.parse_args()
    api = Api(args.url, args.token or None)
    RedBeeTUI(api).run()


if __name__ == "__main__":
    main()
