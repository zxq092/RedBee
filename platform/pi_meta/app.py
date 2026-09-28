"""Pi Meta gateway: web + session + dispatch + report aggregation.

Self-developed layer (doc 11.1: Pi is the only layer we build on). The Pi coding-agent
engine is behind an abstraction; in the mock phase the dispatcher drives agent adapters
that exercise the real RED-KB query_kb/submit_case tools.
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
import asyncio
import json
import os
import re
import uuid

from shared.kb_client import KBClient
from . import sessions
from . import task_logs
from .model_router import ModelRouter
from . import board as board_mod
from . import web_auth
from .orchestrator import orchestrate
from agents import AGENT_META
from agents import task_registry


REDKB_URL = os.environ.get("REDKB_URL", "http://127.0.0.1:8001")
WEB_DIR = os.path.join(os.path.dirname(__file__), "web")

kb = KBClient(REDKB_URL)
router = ModelRouter()
# 真实分发后台任务簿: task_id -> asyncio.Task
_BG_TASKS: dict[str, asyncio.Task] = {}
# 实时槽位进度视图: task_id -> live(由 orchestrate 的 on_progress 更新)
_LIVE: dict[str, dict] = {}
# SSE 事件队列: task_id -> asyncio.Queue(on_progress 每 tool call 推一条, 结束推 None 哨兵)
_LIVE_Q: dict[str, "asyncio.Queue"] = {}


def _new_task_id() -> str:
    return f"t{uuid.uuid4().hex}"

from contextlib import asynccontextmanager


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # 启动：网关重启后内存态任务已丢，把遗留 running 的 task 标记为 interrupted
    # （否则前端会误连死任务的 SSE）。
    try:
        stale = sessions.list_tasks(status="running")
        for t in stale:
            meta = sessions.get_task_metadata(t["task_id"])
            sessions.save_task_metadata(
                t["task_id"], meta.get("target", ""), meta.get("target_id", ""),
                meta.get("model", ""), meta.get("agents") or [], meta.get("assigned_modules") or [],
                "interrupted", session_id=meta.get("session_id", ""))
            print(f"[startup] 遗留 running 任务标记 interrupted: {t['task_id']}", flush=True)
    except Exception as e:
        print(f"[startup] stale task cleanup error: {type(e).__name__}: {e}", flush=True)
    # 孤儿沙箱清理：内存态已丢，任何存活的 inhouse-sess-* 都属上个死进程 → 全杀
    try:
        from agents.executor import kill_orphan_containers
        k = await kill_orphan_containers("inhouse-sess-,inhouse-task-")
        if k:
            print(f"[startup] 清理 {k} 个孤儿 inhouse-sess-* 容器", flush=True)
    except Exception as e:
        print(f"[startup] orphan container cleanup error: {type(e).__name__}: {e}", flush=True)
    yield


app = FastAPI(title="Pi Meta Gateway", version="1.0", lifespan=_lifespan)
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


def _check_auth(request: Request):
    """写操作鉴权：未启用(PIMETA_WEB_TOKEN 空)则放行；否则校验 Bearer session token。"""
    if not web_auth.auth_enabled():
        return None
    hdr = request.headers.get("authorization", "")
    token = hdr[7:] if hdr.lower().startswith("bearer ") else ""
    if not web_auth.check_session(token):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return None


@app.post("/api/login")
async def api_login(request: Request):
    """正式对外模式登录：body {"token": <PIMETA_WEB_TOKEN>} → {session_token}。"""
    if not web_auth.auth_enabled():
        return JSONResponse({"error": "auth disabled"}, status_code=400)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)
    token = (body or {}).get("token", "")
    session = web_auth.issue_session(token if isinstance(token, str) else "")
    if session is None:
        return JSONResponse({"error": "invalid token"}, status_code=401)
    return {"ok": True, "session_token": session}


@app.get("/", response_class=HTMLResponse)
async def index():
    with open(os.path.join(WEB_DIR, "index.html"), encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), headers={"Cache-Control": "no-cache"})


@app.get("/api/agents")
async def list_agents():
    return [{"id": k, **v} for k, v in AGENT_META.items()]


@app.get("/api/models")
async def list_models():
    return {
        "default_priority": router.model_priority,
        "effective_priority": router.model_priority,
        "override": router.override,
        "base_priority": list(getattr(router, "_base_priority", router.model_priority)),
        "auth_enabled": web_auth.auth_enabled(),
    }


@app.post("/api/models/override")
async def set_model_override(request: Request):
    """运行时手动指定模型（前端模型下拉）。body: {"model": "DeepSeek-V4-Flash"} 或 {"model": ""} 恢复默认。"""
    denied = _check_auth(request)
    if denied is not None:
        return denied
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)
    model = (body or {}).get("model", "")
    if not isinstance(model, str):
        return JSONResponse({"error": "model must be a string"}, status_code=400)
    try:
        if model.strip():
            router.set_override(model)
        else:
            router.clear_override()
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return {
        "ok": True,
        "override": router.override,
        "effective_priority": router.model_priority,
    }


@app.get("/api/sessions")
async def api_list_sessions():
    return sessions.list_sessions()


@app.post("/api/sessions")
async def api_create_session(request: Request):
    denied = _check_auth(request)
    if denied is not None:
        return denied
    body = await request.json()
    title = (body.get("title") or "新会话").strip() or "新会话"
    return {"id": sessions.create_session(title=title)}


@app.get("/api/sessions/{sid}/messages")
async def api_messages(sid: str):
    return sessions.get_messages(sid)


@app.patch("/api/sessions/{sid}")
async def api_rename_session(sid: str, request: Request):
    denied = _check_auth(request)
    if denied is not None:
        return denied
    body = await request.json()
    ok = sessions.rename_session(sid, body.get("title", ""))
    if not ok:
        return JSONResponse({"error": "title empty or session not found"}, status_code=404)
    return {"ok": True, "id": sid}


@app.delete("/api/sessions/{sid}")
async def api_delete_session(sid: str, request: Request):
    denied = _check_auth(request)
    if denied is not None:
        return denied
    if not sessions.delete_session(sid):
        return JSONResponse({"error": "该会话有运行中任务，请先停止任务再删除"}, status_code=409)
    return {"ok": True}


@app.post("/api/sessions/bulk-delete")
async def api_bulk_delete_sessions(request: Request):
    """批量删除会话（连带各自 messages/reports）。body {"ids": [...]}。"""
    denied = _check_auth(request)
    if denied is not None:
        return denied
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)
    ids = body.get("ids", [])
    if not isinstance(ids, list):
        return JSONResponse({"error": "ids must be a list"}, status_code=400)
    n = 0
    skipped = 0
    for sid in ids:
        if isinstance(sid, str) and sid.strip():
            if sessions.delete_session(sid.strip()):
                n += 1
            else:
                skipped += 1
    return {"ok": True, "deleted": n, "skipped": skipped}


@app.post("/api/task")
async def run_task(payload: Request):
    denied = _check_auth(payload)
    if denied is not None:
        return denied
    body = await payload.json()
    sid = body.get("session_id")
    task = body.get("task", "")
    target = body.get("target", "")
    target_id = body.get("target_id", "")  # 稳定 KB 标识（dvwa）；空则从 target 推断
    agents = body.get("agents", []) or list(AGENT_META.keys())

    # 每任务参数覆盖（可选）：并发/模块数/轮次/预算/重试/侦察开关，只作用于本任务
    # 契约位置是 body["params"] 对象；顶层同名字段作兜底（治调用方放错位置被静默丢弃）
    from .real_dispatch import validate_task_params, TASK_PARAM_SPECS
    raw_params = body.get("params")
    if not isinstance(raw_params, dict):
        raw_params = {}
    for k in TASK_PARAM_SPECS:
        if k not in raw_params and k in body:
            raw_params[k] = body[k]
    task_params, param_errs = validate_task_params(raw_params)
    if param_errs:
        print(f"[task:dispatch] params 剔除非法项: {param_errs}", flush=True)

    if not sid:
        return JSONResponse({"error": "session_id required"}, status_code=400)
    # 一会话一任务（串行模型）：同会话已有 running 任务 → 拒绝，防双击派发/跨标签页并发
    if sessions.has_running_task(sid):
        return JSONResponse(
            {"error": "该会话已有任务在运行，请等待完成或先停止（一会话一任务）"},
            status_code=409)

    sessions.ensure_session(sid, title=f"任务: {task[:40]}")
    sessions.autotitle_if_default(sid, f"任务: {task[:30]}")
    sessions.add_message(sid, "user", f"任务: {task}  目标: {target}")

    # Pi 网关: 把任务异步分发给真实 agent(不阻塞 Web 返回)
    task_id = _new_task_id()
    _LIVE_Q[task_id] = asyncio.Queue()
    bg = asyncio.create_task(
        _run_real(agents, task, target, sid, task_id, target_id, task_params=task_params)
    )
    _BG_TASKS[task_id] = bg
    task_registry.register(task_id, bg)
    task_logs.log(task_id, "dispatch",
                  f"target={target} target_id={target_id} agents={','.join(agents)} "
                  f"params={task_params or '-'} text={task[:160]}")

    return {
        "task_id": task_id,
        "status": "dispatched",
        "agents": agents,
        "target": target,
        "params": task_params,
        "param_warnings": param_errs,
        "note": "已分发给自研 RedBee agent 后台执行",
    }


@app.get("/api/task/{task_id}")
async def task_status(task_id: str):
    t = _BG_TASKS.get(task_id)
    if t is None:
        return JSONResponse({"error": "unknown task_id"}, status_code=404)
    if not t.done():
        return {"task_id": task_id, "status": "running",
                "live": _LIVE.get(task_id, {"slots": {}, "queue": [], "verify_q": []})}
    try:
        res = t.result()
    except Exception as e:
        return {"task_id": task_id, "status": "error", "error": str(e)}
    return {"task_id": task_id, "status": "done", "result": res}


@app.get("/api/task/{task_id}/meta")
async def task_meta(task_id: str):
    """任务持久元数据（DB 真源，网关重启后也可查）：状态/时长起止/模型/运行错误摘要。"""
    meta = sessions.get_task_metadata(task_id)
    if not meta:
        return JSONResponse({"error": "unknown task_id"}, status_code=404)
    return meta


@app.get("/api/task/{task_id}/live")
async def task_live(task_id: str):
    """实时视图: 每个槽位 agent 当前的模块/flow/进度 + 剩余队列。"""
    if task_id not in _LIVE:
        return {"task_id": task_id, "slots": {}, "queue": [], "verify_q": []}
    return {"task_id": task_id, **_LIVE[task_id]}


async def _delayed_cleanup(task_id: str, delay: int = 600):
    """任务结束后延迟清理 SSE 队列（给 /stream 客户端留出消费/重连窗口）。"""
    await asyncio.sleep(delay)
    _LIVE_Q.pop(task_id, None)


@app.get("/api/task/{task_id}/stream")
async def task_stream(task_id: str):
    """SSE 实时流：逐 tool call 推送 agent 执行进度（豆包式推送，免轮询）。

    客户端: `curl -N /api/task/{id}/stream` 或浏览器 EventSource。
    每行 `data: {json}\n\n`；type=live 是槽位快照，type=done 表示结束。
    连接后先回补当前 _LIVE 快照，再推后续 progress_cb 事件，直到任务结束。"""
    q = _LIVE_Q.get(task_id)
    if q is None:
        return JSONResponse({"error": "unknown or finished task"}, status_code=404)

    async def gen():
        bg = _BG_TASKS.get(task_id)

        def _live(ev: dict) -> str:
            return f"data: {json.dumps({'type': 'live', **ev}, ensure_ascii=False)}\n\n"

        def _done(reason: str = "") -> str:
            payload = {'type': 'done'}
            if reason:
                payload['reason'] = reason
            return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

        if task_id in _LIVE:
            yield _live(_LIVE[task_id])
        # 先非阻塞吐出队列里已累积的事件（连接晚于任务启动/结束的场景）
        while True:
            try:
                ev = q.get_nowait()
            except asyncio.QueueEmpty:
                break
            if ev is None:
                yield _done()
                return
            yield _live(ev)
        # 任务已结束且队列空 → 立即 done（免等 15s keepalive）
        if bg is not None and bg.done() and q.empty():
            yield _done("task_finished")
            return
        # 主循环：等待新事件
        while True:
            try:
                ev = await asyncio.wait_for(q.get(), timeout=15)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"  # SSE 注释行保活，防中间代理断连
                if bg is not None and bg.done() and q.empty():
                    yield _done("task_finished")
                    break
                continue
            if ev is None:  # 哨兵
                yield _done()
                break
            yield _live(ev)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


async def _probe_target(target: str, timeout: float = 5.0) -> tuple:
    """可达性预检：对 target 做一次 HTTP GET（宿主网络），返回 (是否可达, 说明)。

    治"乱目标/不可达目标慢速烧预算"：派发前 3~5s 内判定，不可达直接快速失败，
    一条侦察/利用轮都不烧。target 空 → 不可达(未提供)。非 http 前缀默认补 http://。
    """
    if not target or not target.strip():
        return False, "未提供目标地址"
    url = target.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        import httpx
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.get(url)
            return True, f"HTTP {r.status_code}"
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:140]}"


async def _run_real(agents, task, target, sid, task_id, target_id: str = "", task_params: dict = None):
    def on_event(kind: str, detail: str):
        # 漏洞板事件不再逐条贴进会话（前端执行卡的漏洞板区就是板，避免双份显示）；
        # 只留日志（网关 stdout + per-task 执行日志落库）
        print(f"[board:{task_id}] {kind} | {detail}", flush=True)
        task_logs.log(task_id, "board", f"{kind} | {detail}")

    def on_progress(live: dict):
        _LIVE[task_id] = live
        q = _LIVE_Q.get(task_id)
        if q is not None:
            try:
                q.put_nowait(dict(live))
            except Exception:
                pass

    cancelled = False
    run_error = ""
    try:
        # 可达性预检：目标不可达 → 快速失败（不烧侦察/利用预算，秒级返回明确错误）
        ok, detail = await _probe_target(target)
        if not ok:
            raise RuntimeError(f"目标不可达 {target} — {detail}。请检查地址/端口/网络后重试。")
        results = await orchestrate(task_id, agents, task, target, on_event=on_event,
                                    on_progress=on_progress, target_id=target_id,
                                    session_id=sid, task_params=task_params)
    except asyncio.CancelledError:
        cancelled = True
        results = []
    except Exception as e:
        run_error = str(e)
        results = []
    finally:
        _LIVE.pop(task_id, None)
        task_registry.clear(task_id)  # 清理 in-run steer 的 agent 注册/指令缓冲

    # 汇总报告 + 落库：v2 编排的 finding 都在 findings 表(board)，
    # 用 report_builder 从 board 读真实 findings 生成完整报告（含 PoC/覆盖对账）。
    # 取消/出错时同样基于已贴板的 findings 出部分报告（stop 不丢成果）。
    from . import report_builder
    metadata = sessions.get_task_metadata(task_id)
    findings = report_builder.query_findings(task_id)
    coverage = {"rows": report_builder.query_coverage(task_id),
                "assigned_modules": metadata.get("assigned_modules") or [],
                "target": metadata.get("target") or target}
    report_md = report_builder.build_markdown_report(task_id, findings, coverage)
    total = len([f for f in findings
                 if str(f.get("status", "found")).lower() not in {"false_positive", "suspect"}])
    status_counts: dict[str, int] = {}
    for f in findings:
        status = str(f.get("status", "found")).lower()
        status_counts[status] = status_counts.get(status, 0) + 1
    agg = {"total_findings": total, "findings": findings, "status_counts": status_counts,
           "assigned_modules": coverage["assigned_modules"], "target": coverage["target"],
           "model": metadata.get("model") or "RedBee"}
    final_status = "cancelled" if cancelled else ("runtime_error" if run_error else "done")
    # 持久化失败原因（runtime_error_summary），前端状态行/任务记录据此展示"为什么失败/中断"
    sessions.save_task_metadata(
        task_id, target, target_id or metadata.get("target_id", ""), metadata.get("model", ""),
        list(agents), agg["assigned_modules"], final_status,
        runtime_error_summary=(run_error[:200] if (run_error and not cancelled) else ""),
        session_id=sid)
    sessions.save_report(sid, task, target, agg["model"], report_md,
                         {"task_id": task_id, "total": total,
                          "target_id": metadata.get("target_id", ""),
                          "assigned_modules": agg["assigned_modules"],
                          "status": final_status})
    # 任务结果不再往会话存"纯文本结论"消息：结果展示的唯一入口是前端的
    # 任务记录块（renderTaskArtifacts，从 /api/tasks + /board + 报告渲染，
    # 带 ⬇报告/⬇日志 下载）+ 实时执行卡定格。旧数据里的纯文本结论由前端
    # openSession 按前缀过滤不再显示（见 index.html）。
    # 回流闭环：有 finding 时 fire-and-forget 触发 KB distill+promote+sync（不阻塞任务返回）。
    # 治理门禁保证只有 verified 条目才 authoritative。
    if total > 0 and not cancelled:
        asyncio.create_task(_trigger_kb_ingest(task_id))
        # 靶场档案自动沉淀：无档案的 target 从 findings 生成漏洞地图，下次自动热启动免重复描述
        try:
            from agents.tools import resolve_target_id as _rtid
            from . import target_profile as _tp
            _tid = _rtid(target, target_id)
            _p = _tp.build_target_profile(task_id, target, _tid)
            if _p:
                print(f"[target-profile] task={task_id} 自动建档 {_p}", flush=True)
        except Exception as e:
            print(f"[target-profile] task={task_id} error: {type(e).__name__}: {e}", flush=True)
    # SSE 哨兵：通知 /stream 端点任务结束（成功/取消/异常路径统一）
    q = _LIVE_Q.get(task_id)
    if q is not None:
        try:
            q.put_nowait({"type": "final", "status": final_status})
        except Exception:
            pass
        try:
            q.put_nowait(None)
        except Exception:
            pass
        asyncio.create_task(_delayed_cleanup(task_id))
    task_logs.log(task_id, "final",
                  f"status={final_status} valid_findings={total}" + (f" run_error={run_error[:160]}" if run_error else ""))
    return {"agents": results, "aggregate": agg, "status": final_status}


async def _trigger_kb_ingest(task_id: str):
    """任务完成后自动回流：distill case → promote authoritative。失败不影响任务。"""
    try:
        from auto_ingest import process_task
        res = await process_task(task_id)
        if res.get("ok"):
            print(f"[kb-ingest] task={task_id} promoted={res.get('promoted')} sync={res.get('sync', {}).get('exit')}", flush=True)
        else:
            print(f"[kb-ingest] task={task_id} failed: {res.get('error')}", flush=True)
    except Exception as e:
        print(f"[kb-ingest] task={task_id} error: {type(e).__name__}: {e}", flush=True)


@app.get("/api/task/{task_id}/board")
async def task_board(task_id: str):
    """漏洞板实时视图: found/confirmed/false_positive 全量 + 任务状态。

    status 供前端轮询做"完成检测"（SSE 流断了也能发现任务已结束，防卡片卡死在运行中）。"""
    meta = sessions.get_task_metadata(task_id) or {}
    bg = _BG_TASKS.get(task_id)
    # 有存活后台任务 = running；否则用已落库的终态。内存/状态都查不到时(如网关重启后的孤儿任务)
    # 绝不回退成 running——否则历史会话会永远顶着一个"运行中"绿点。此时按 interrupted 处理更真实。
    if bg is not None and not bg.done():
        status = "running"
    else:
        status = meta.get("status") or "interrupted"
    return {"task_id": task_id, "findings": board_mod.all_findings(task_id), "status": status}


@app.patch("/api/task/{task_id}/findings/{fid}")
async def api_finding_status(task_id: str, fid: int, request: Request):
    """前端手动流转 finding 状态：confirmed / false_positive / found（回退）。
    board.mark() 早已支持，此处只是暴露 HTTP 入口（治"误报只能在库里改"）。"""
    denied = _check_auth(request)
    if denied is not None:
        return denied
    try:
        body = await request.json()
    except Exception:
        body = {}
    status = str(body.get("status", ""))
    if status not in ("confirmed", "false_positive", "found"):
        return JSONResponse(
            {"error": "status must be one of confirmed/false_positive/found"},
            status_code=400)
    board_mod.mark(task_id, fid, status, confirmed_by=str(body.get("confirmed_by") or "ui"))
    return {"ok": True, "task_id": task_id, "id": fid, "status": status}


def _report_payload(task_id: str):
    """从 pimeta.db 读 findings+coverage → 生成 Markdown 报告。无数据返回 None。"""
    from . import report_builder
    metadata = sessions.get_task_metadata(task_id)
    findings = report_builder.query_findings(task_id)
    if not metadata and not findings:
        return None
    rows = report_builder.query_coverage(task_id)
    coverage = {
        "rows": rows,
        "assigned_modules": (metadata or {}).get("assigned_modules") or [],
        "target": (metadata or {}).get("target") or (findings[0].get("target") if findings else ""),
    }
    report_md = report_builder.build_markdown_report(task_id, findings, coverage)
    return {"task_id": task_id, "report_md": report_md, "raw_findings": findings}


@app.get("/api/task/{task_id}/report")
async def task_report(task_id: str):
    """正式渗透测试报告: 从 pimeta.db 读 findings+coverage → 生成 Markdown 报告。

    新增端点, 不动现有 board/live 逻辑; 只在 task_id 下确实有数据时成功, 否则 404。
    """
    payload = _report_payload(task_id)
    if payload is None:
        return JSONResponse({"error": "unknown task_id"}, status_code=404)
    return payload


@app.get("/api/task/{task_id}/report/download")
async def task_report_download(task_id: str):
    """下载报告为 .md 文件（浏览器直接下载 / 可作链接）。"""
    payload = _report_payload(task_id)
    if payload is None:
        return JSONResponse({"error": "unknown task_id"}, status_code=404)
    fname = f"pentest_report_{task_id}.md"
    return Response(
        content=payload["report_md"],
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{fname}"},
    )


@app.get("/api/task/{task_id}/log")
async def task_log(task_id: str):
    """任务执行日志（结构化行，时间序；供 UI/调试）。"""
    if not sessions.get_task_metadata(task_id):
        return JSONResponse({"error": "unknown task_id"}, status_code=404)
    return {"task_id": task_id, "lines": task_logs.query(task_id)}


@app.get("/api/task/{task_id}/log/download")
async def task_log_download(task_id: str):
    """下载执行日志为 .txt（人类可读时间线：派发/相位/LLM/工具/发现/失败/指令/停止）。"""
    meta = sessions.get_task_metadata(task_id) or {}
    fname = f"pentest_log_{task_id}.txt"
    return Response(
        content=task_logs.render_text(task_id, meta),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{fname}"},
    )


@app.get("/api/sessions/{sid}/reports")
async def api_reports(sid: str):
    return sessions.get_reports(sid)


@app.get("/api/tasks")
async def api_tasks(status: str = ""):
    """任务列表（含 running），供前端刷新后恢复进行中任务。

    富化字段：findings=有效发现数；modules_total/modules_done（左栏进度条/模块地图）。
    """
    tasks = sessions.list_tasks(status)
    for t in tasks:
        tid = t.get("task_id") or ""
        try:
            fs = board_mod.all_findings(tid)
            t["findings"] = sum(1 for f in fs
                                if str(f.get("status", "found")).lower() not in ("", "false_positive"))
            t["modules_total"] = len(t.get("assigned_modules") or [])
            t["modules_done"] = task_logs.count_kinds(tid, ("module_done", "module_fail"))
        except Exception:
            t.setdefault("findings", 0)
            t.setdefault("modules_total", 0)
            t.setdefault("modules_done", 0)
    return tasks


@app.get("/api/targets")
async def api_targets():
    """已知靶场档案清单（data/targets/*.md），供目标输入下拉。"""
    d = os.path.join(sessions.DATA_DIR, "targets")
    out = []
    if os.path.isdir(d):
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".md"):
                continue
            tid = fn[:-3]
            addr = ""
            try:
                with open(os.path.join(d, fn), encoding="utf-8") as f:
                    m = re.search(r"`(https?://[^`\s]+)`", f.read())
                    if m:
                        addr = m.group(1)
            except Exception:
                pass
            out.append({"id": tid, "name": tid, "addr": addr})
    return out


@app.post("/api/task/{task_id}/cancel")
async def task_cancel(task_id: str, request: Request):
    """停止任务：cancel 所有登记 asyncio 任务 + 物理杀沙箱容器。"""
    denied = _check_auth(request)
    if denied is not None:
        return denied
    bg = _BG_TASKS.get(task_id)
    if bg is None or bg.done():
        meta = sessions.get_task_metadata(task_id)
        if not meta:
            return JSONResponse({"error": "unknown task_id"}, status_code=404)
        task_registry.mark_cancelled(task_id)
        try:
            k = await task_registry.kill_containers(task_id)
        except Exception:
            k = 0
        sessions.save_task_metadata(
            task_id, meta.get("target", ""), meta.get("target_id", ""), meta.get("model", ""),
            meta.get("agents") or [], meta.get("assigned_modules") or [], "cancelled",
            session_id=meta.get("session_id", ""))
        task_logs.log(task_id, "stop", f"cancelled=0 containers_killed={k}（任务未在运行）")
        return {"ok": True, "cancelled": 0, "containers_killed": k, "note": "task not running"}
    res = await task_registry.cancel_task(task_id)
    print(f"[cancel] task={task_id} {res}", flush=True)
    task_logs.log(task_id, "stop", f"cancelled={res.get('cancelled')} containers_killed={res.get('containers_killed', 0)}")
    return {"ok": True, **res}


@app.post("/api/task/{task_id}/message")
async def task_message(task_id: str, request: Request):
    """飞行中指令（in-run steer）：注入任务运行中 agent，从各自下一个 LLM 轮次生效。

    body: {"text": "...", "modules": ["xss"]}（modules 可选）
      modules 省略/空 → 全局指令（scope=all，所有运行中 agent 收）
      modules=[...]  → 定向指令（仅指定模块的专员收，其他模块不被打扰）
    相位间隙（无 agent 在跑）不丢：进任务级 steer 日志，之后诞生的 agent
    注册时按作用域继承（整批新 agent 全覆盖）。"""
    denied = _check_auth(request)
    if denied is not None:
        return denied
    try:
        body = await request.json()
    except Exception:
        body = {}
    text = str((body or {}).get("text", "")).strip()
    if not text:
        return JSONResponse({"error": "text required"}, status_code=400)
    bg = _BG_TASKS.get(task_id)
    if bg is None or bg.done():
        return JSONResponse({"error": "task not running"}, status_code=404)
    modules = (body or {}).get("modules")
    if isinstance(modules, str):
        modules = [modules]
    if modules is not None and not isinstance(modules, list):
        modules = None
    if modules is not None:
        modules = [str(m).strip() for m in modules if str(m).strip()] or None
    n = task_registry.add_note(task_id, text, modules)
    scope_tag = f"（作用域: {', '.join(modules)}）" if modules else ""
    task_logs.log(task_id, "steer", f"飞行中指令（注入 {n} 个 agent）{scope_tag}: {text[:160]}")
    meta = sessions.get_task_metadata(task_id) or {}
    sid = meta.get("session_id", "")
    if sid:
        sessions.add_message(sid, "user", text)
        sessions.add_message(
            sid, "assistant",
            f"[指令] 已注入 {n} 个运行中 agent{scope_tag}（下一轮生效）" if n
            else f"[指令] 已收到{scope_tag}（当前相位间隙无运行中 agent，将在下一批子 agent 自动注入）")
    return {"ok": True, "injected": n}


@app.get("/healthz")
async def health():
    return {"status": "ok"}
