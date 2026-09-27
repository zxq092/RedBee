#!/usr/bin/env python3
"""Web UI 全量回归测试（playwright 无头浏览器，需网关在跑）。

用途：**每次改动 pi_meta/web/index.html（或相关后端端点）提交前必跑**，
全绿才允许提交。覆盖所有交互流程 + 历史踩坑的回归点：

  1.  首屏加载 + 会话列表 + 全程零 JS 错误
  2.  主题（暗/亮切换，漏洞板颜色实锤——暗色变量自引用失效坑的回归）
  3.  历史会话重载：每条任务消息下内联一条任务记录（顺序对应、无末尾块）
  4.  状态栏：有 running 任务的会话显示、无的隐藏、切回再显示
  5.  findings 展开板 / 报告预览 modal（Esc 关闭）
  6.  finding 误报标记→恢复（数据还原，不污染）
  7.  批量勾选/全选/取消（sid undefined ReferenceError 坑的回归）
  8.  任务总览：打开/过滤/打开定位/切回会话/切回新建会话
      （"点任务总览后点会话切不回来"坑的回归）
  9.  重跑：运行中会话守卫 + 干净会话文本还原
  10. 语言切换（中/EN）

运行：cd platform && python3 tests/web_e2e.py
退出码：0=全绿，1=有失败。
环境变量：WEB_E2E_BASE（默认 http://127.0.0.1:8100）
"""
import asyncio
import json
import os
import sys

BASE = os.environ.get("WEB_E2E_BASE", "http://127.0.0.1:8100")

RESULTS = []

def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))
    return bool(cond)


async def run():
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        b = await p.chromium.launch(args=["--no-sandbox", "--disable-gpu"])
        pg = await b.new_page(viewport={"width": 1400, "height": 900})
        errors = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        await pg.goto(BASE, wait_until="domcontentloaded", timeout=30000)
        await pg.wait_for_timeout(2500)

        # ---- 后端数据快照（选测试对象用） ----
        d = await pg.evaluate(f"""async ()=>{{
            const tasks = await (await fetch('/api/tasks')).json();
            const sessions = await (await fetch('/api/sessions')).json();
            const running = tasks.filter(t=>t.status==='running');
            // 选历史会话：任务数>=2 且已结束
            let hist=null;
            for (const t of tasks.filter(x=>x.status!=='running')){{
              const same = tasks.filter(x=>x.session_id===t.session_id && x.status!=='running').length;
              if (same>=2){{ hist=t; break; }}
            }}
            return {{
              sessions: sessions.length,
              tasks: tasks.length,
              running: running.map(t=>({{tid:t.task_id, sid:t.session_id}})),
              hist: hist?{{tid:hist.task_id, sid:hist.session_id}}:null
            }};
        }}""")

        # 1. 首屏
        print("[1] 首屏加载")
        n_sess = await pg.evaluate("document.querySelectorAll('#sessionList .sess').length")
        check("会话列表渲染", n_sess == d["sessions"], f"list={n_sess} api={d['sessions']}")

        # 2. 主题
        print("[2] 主题（漏洞板颜色）")
        for mode, bg, title in [("dark", "rgb(13, 17, 23)", "rgb(165, 216, 255)"),
                                ("light", "rgb(233, 238, 245)", "rgb(5, 80, 174)")]:
            await pg.evaluate(f"localStorage.setItem('redbee_theme','{mode}')")
            await pg.reload(wait_until="domcontentloaded")
            await pg.wait_for_timeout(1500)
            r = await pg.evaluate("""()=>{
              const div=document.createElement('div');
              div.innerHTML='<div class="lc-board"><span class="lb-title">x</span></div>';
              document.body.appendChild(div);
              const r={bg:getComputedStyle(div.querySelector('.lc-board')).backgroundColor,
                       title:getComputedStyle(div.querySelector('.lb-title')).color};
              div.remove(); return r;
            }""")
            check(f"{mode} 板底不透明", r["bg"] == bg, str(r))
            check(f"{mode} 标题蓝色", r["title"] == title, str(r))
        await pg.evaluate("localStorage.removeItem('redbee_theme')")
        await pg.reload(wait_until="domcontentloaded")
        await pg.wait_for_timeout(2000)

        # 3. 历史会话：内联任务记录一一对应
        print("[3] 历史会话内联任务记录")
        hist = d["hist"]
        if hist:
            await pg.evaluate(f"openSession('{hist['sid']}')")
            await pg.wait_for_timeout(6000)
            r = await pg.evaluate("""()=>{
              const seq=[...document.querySelectorAll('#msgs > *')].map(e=>{
                if (e.classList.contains('msg')&&e.classList.contains('user')) return 'U';
                if (e.classList.contains('msg')&&e.classList.contains('assistant')){
                  const rows=[...e.querySelectorAll('.artifact-row')];
                  return rows.length?(rows.length>1?'BOX':'R'):'A';
                }
                return 'X';
              });
              const U=seq.filter(x=>x==='U').length;
              const R=seq.filter(x=>x==='R').length;
              const inline=seq.filter((x,i)=>x==='R'&&seq[i-1]==='U').length;
              return {U, R, inline, box: seq.filter(x=>x==='BOX').length,
                      allRAfterU: R===inline};
            }""")
            check("每条任务消息下一条记录", r["allRAfterU"] and r["R"] > 0, json.dumps(r))
            check("无末尾汇总块", r["box"] == 0, json.dumps(r))

        # 4. 状态栏（需要 running 任务才有意义）
        print("[4] 状态栏")
        rt = await pg.evaluate(
            "async()=>{const t=(await (await fetch('/api/tasks?status=running')).json())[0];"
            "return t?{sid:t.session_id}:null}")
        if rt:
            await pg.evaluate(f"openSession('{rt['sid']}')")
            await pg.wait_for_timeout(4000)
            on1 = await pg.evaluate("document.getElementById('runStatus').classList.contains('on')")
            check("running 会话显示状态栏", on1)
            if hist and hist["sid"] != rt["sid"]:
                await pg.evaluate(f"openSession('{hist['sid']}')")
                await pg.wait_for_timeout(4000)
                on2 = await pg.evaluate("document.getElementById('runStatus').classList.contains('on')")
                check("切历史会话状态栏隐藏", not on2)
                await pg.evaluate(f"openSession('{rt['sid']}')")
                await pg.wait_for_timeout(3000)
                on3 = await pg.evaluate("document.getElementById('runStatus').classList.contains('on')")
                check("切回 running 会话状态栏再显示", on3)
        else:
            print("  SKIP  （无运行中任务）")

        # 5. findings 展开 + 报告 modal
        print("[5] findings 展开 / 报告预览")
        await pg.evaluate(f"openSession('{hist['sid']}')")
        await pg.wait_for_timeout(5000)
        r5 = await pg.evaluate("""async ()=>{
          const vb=[...document.querySelectorAll('.artifact-row button')].find(x=>x.textContent.includes('发现'));
          if (!vb) return {hasFindingsBtn:false};
          vb.click();
          const det=vb.closest('.artifact-wrap').querySelector('.record-detail');
          const rows=det?det.querySelectorAll('.lb-row').length:0;
          const rb=[...document.querySelectorAll('.artifact-row button')].find(x=>x.textContent.includes('报告'));
          rb.click();
          await new Promise(r=>setTimeout(r,1500));
          const ov=document.getElementById('mdOverlay');
          const shown=ov&&ov.style.display!=='none';
          // 合成键盘事件必须 bubbles:true 才能从 body 冒泡到 document 的 Esc 监听
          document.body.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
          await new Promise(r=>setTimeout(r,300));
          const closed=ov.style.display==='none';
          return {hasFindingsBtn:true, rows, modalShown:shown, escClosed:closed};
        }""")
        check("📋 发现展开板", r5.get("rows", 0) > 0, json.dumps(r5))
        check("📖 报告 modal 打开", r5.get("modalShown"))
        check("Esc 关闭 modal", r5.get("escClosed"))

        # 6. 误报标记→恢复（还原数据）
        print("[6] finding 误报标记/恢复")
        r6 = await pg.evaluate("""async ()=>{
          const vb=[...document.querySelectorAll('.artifact-row button')].find(x=>x.textContent.includes('发现'));
          // 步骤5可能已展开（点击是 toggle）：只在收起时点开
          const det0=vb.closest('.artifact-wrap').querySelector('.record-detail');
          if (det0.style.display==='none') vb.click();
          await new Promise(r=>setTimeout(r,500));
          const det=[...document.querySelectorAll('.record-detail')].find(x=>x.style.display!=='none' && x.children.length);
          const row=det.querySelector('.lb-row');
          if (!row) return {ok:false, why:'no row'};
          // 直接点行内按钮（误报→恢复），状态经 PATCH 落库
          const btn=[...row.querySelectorAll('.f-act')].find(x=>x.textContent.trim()==='误报');
          if (!btn) return {ok:false, why:'no fp btn (already fp?)', st0};
          btn.click();
          await new Promise(r=>setTimeout(r,2500));
          const det2=[...document.querySelectorAll('.record-detail')].find(x=>x.style.display!=='none' && x.children.length);
          const fpN=det2.querySelectorAll('.lb-row.lb-fp').length;
          // 还原：找到该行点"恢复"
          const rows2=[...det2.querySelectorAll('.lb-row.lb-fp')];
          const r2=rows2[rows2.length-1];
          const rb=[...r2.querySelectorAll('.f-act')].find(x=>x.textContent.trim()==='恢复');
          rb.click();
          await new Promise(r=>setTimeout(r,2500));
          const det3=[...document.querySelectorAll('.record-detail')].find(x=>x.style.display!=='none' && x.children.length);
          const fpN2=det3.querySelectorAll('.lb-row.lb-fp').length;
          return {ok:true, fpAfterMark:fpN, fpAfterRestore:fpN2};
        }""")
        check("标记误报生效", r6.get("fpAfterMark", 0) >= 1, json.dumps(r6))
        check("恢复后还原", r6.get("fpAfterRestore", -1) == max(0, r6.get("fpAfterMark", 1) - 1), json.dumps(r6))

        # 7. 批量勾选（sid undefined 坑的回归）
        print("[7] 批量勾选")
        r7 = await pg.evaluate("""()=>{
          const ck=[...document.querySelectorAll('#sessionList .sess .ck')].find(c=>!c.disabled);
          if (!ck) return {ok:false};
          ck.click();
          const sel1=document.querySelectorAll('#sessionList .sess.selected').length;
          document.getElementById('selectAll').click();
          const sel2=document.querySelectorAll('#sessionList .sess.selected').length;
          const btn=document.getElementById('bulkDelBtn').textContent;
          document.getElementById('selectAll').click();
          const sel3=document.querySelectorAll('#sessionList .sess.selected').length;
          return {ok:true, sel1, sel2, btn, sel3};
        }""")
        check("单个勾选", r7.get("sel1") == 1, json.dumps(r7))
        check("全选", r7.get("sel2", 0) > 1)
        check("取消全选", r7.get("sel3") == 0)

        # 8. 任务总览 + 切回（"切不回来"坑的回归）
        print("[8] 任务总览")
        await pg.evaluate("document.getElementById('taskViewBtn').click()")
        await pg.wait_for_timeout(1500)
        r8 = await pg.evaluate("""()=>{
          const rows=document.querySelectorAll('#tvBody tr').length;
          const count=document.querySelector('.tv-count').textContent;
          return {rows, count, chatHidden:document.getElementById('chatView').style.display==='none'};
        }""")
        check("总览表格渲染", r8["rows"] == d["tasks"], json.dumps(r8))
        check("聊天视图隐藏", r8["chatHidden"])
        # 过滤
        await pg.select_option("#tvStatus", "done")
        await pg.wait_for_timeout(1000)
        r8b = await pg.evaluate("({rows:document.querySelectorAll('#tvBody tr').length,"
                                "allDone:[...document.querySelectorAll('#tvBody .status-pill')].every(x=>x.textContent==='完成')})")
        check("状态过滤", r8b["rows"] > 0 and r8b["allDone"], json.dumps(r8b))
        await pg.select_option("#tvStatus", "")
        await pg.wait_for_timeout(800)
        # 打开定位
        r8c = await pg.evaluate("""async ()=>{
          const row=[...document.querySelectorAll('#tvBody tr')].find(tr=>[...tr.querySelectorAll('.status-pill')].some(p=>p.textContent==='完成'));
          if (!row) return {ok:false};
          const tid=row.querySelector('.tv-tid').textContent;
          [...row.querySelectorAll('button')].find(x=>x.textContent.trim()==='打开').click();
          await new Promise(r=>setTimeout(r,2000));
          const flash=document.querySelector('.flash-rec');
          return {ok:true, flash:!!flash, match:flash?flash.dataset.task.slice(0,10)===tid:false};
        }""")
        check("打开+定位闪烁", r8c.get("flash") and r8c.get("match"), json.dumps(r8c))
        # 关键回归：总览→点会话 切回
        await pg.evaluate("document.getElementById('taskViewBtn').click()")
        await pg.wait_for_timeout(1000)
        await pg.evaluate(f"document.querySelectorAll('#sessionList .sess').forEach(e=>{{if(e.dataset.sid==='{hist['sid']}')e.click()}})")
        await pg.wait_for_timeout(5000)
        r8d = await pg.evaluate("""({tv:document.getElementById('taskView').style.display,
              chat:document.getElementById('chatView').style.display,
              btnOn:document.getElementById('taskViewBtn').classList.contains('on')})""")
        check("总览→点会话切回聊天", r8d["tv"] == "none" and r8d["chat"] == "" and not r8d["btnOn"], json.dumps(r8d))
        # 总览→新建会话 切回
        await pg.evaluate("document.getElementById('taskViewBtn').click()")
        await pg.wait_for_timeout(800)
        await pg.evaluate("document.getElementById('newbtn').click()")
        await pg.wait_for_timeout(1500)
        r8e = await pg.evaluate("""async ()=>{
          const r={tv:document.getElementById('taskView').style.display,
                   chat:document.getElementById('chatView').style.display,
                   empty:!!document.getElementById('empty')};
          // 自清理：测试创建的会话当场删掉，不污染用户的会话列表
          const sid=curSid;
          try { await fetch('/api/sessions/'+sid,{method:'DELETE'}); r.cleaned=sid; } catch(e){}
          return r;
        }""")
        check("总览→新建会话切回聊天", r8e["tv"] == "none" and r8e["chat"] == "" and r8e["empty"], json.dumps(r8e))

        # 9. 重跑（动态查运行态：用户可能恰好有任务在跑，守卫/文本还原都要自适应）
        print("[9] 重跑")
        run9 = await pg.evaluate(
            "async()=>(await (await fetch('/api/tasks?status=running')).json()).length>0")
        if run9:
            r9 = await pg.evaluate("""async ()=>{
              const t=(await (await fetch('/api/tasks')).json()).find(x=>x.status==='running');
              let called=0; const orig=window.sendTask;
              window.sendTask=async()=>{called++;};
              await window.rerunTask(t);
              window.sendTask=orig;
              return {called};
            }""")
            check("运行中任务重跑被拒", r9.get("called") == 0, json.dumps(r9))
        else:
            print("  SKIP  （无运行中任务，守卫分支未覆盖）")
        r9b = await pg.evaluate("""async ()=>{
          const runningSess=new Set((await (await fetch('/api/tasks')).json())
            .filter(x=>x.status==='running').map(x=>x.session_id));
          const sess=await (await fetch('/api/sessions')).json();
          const order=[__HIST_SID__, curSid, ...sess.map(s=>s.id)];   // 优先历史会话
          let cap=null, tried=[];
          const orig=window.sendTask;
          window.sendTask=async()=>{cap={len:document.getElementById('taskInput').value.length,
                                         target:document.getElementById('targetInput').value};};
          for (const sid of order) {
            if (runningSess.has(sid)) continue;          // 避开有 running 任务的会话（守卫会拒）
            try { openSession(sid); } catch(e){ continue; }
            await new Promise(r=>setTimeout(r,2500));
            const row=document.querySelector('.artifact-row[data-task]');
            if (!row) continue;
            const t=(await (await fetch('/api/tasks')).json()).find(x=>x.task_id===row.dataset.task);
            if (!t) continue;
            tried.push(sid);
            await window.rerunTask(t);
            if (cap) break;
          }
          window.sendTask=orig;
          return {cap, tried};
        }""".replace("__HIST_SID__", repr(hist["sid"])))
        if not r9b.get("tried"):
            print("  SKIP  （没有无 running 任务且含任务记录的会话）")
        else:
            check("重跑还原任务文本+目标", r9b.get("cap") and r9b["cap"]["len"] > 20 and r9b["cap"]["target"], json.dumps(r9b))

        # 10. 语言切换
        print("[10] 语言切换")
        r10 = await pg.evaluate("""()=>{
          const before=document.getElementById('newbtn').textContent;
          document.getElementById('langBtn').click();
          const after=document.getElementById('newbtn').textContent;
          const lang=document.documentElement.lang;
          document.getElementById('langBtn').click();  // 切回
          return {before, after, lang};
        }""")
        check("切换生效", r10["before"] != r10["after"] and r10["lang"] in ("zh-CN", "en"), json.dumps(r10))

        # 汇总：零 JS 错误
        print("[*] 全程 JS 错误")
        check("零 pageerror", len(errors) == 0, "; ".join(errors[:3]))
        await b.close()

    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{'='*50}\n结果: {len(RESULTS)-len(failed)}/{len(RESULTS)} 通过")
    if failed:
        print("失败项:")
        for name, _, detail in failed:
            print(f"  ✗ {name}  {detail}")
        sys.exit(1)
    print("ALL GREEN ✓")


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except Exception as e:
        print(f"FATAL: {type(e).__name__}: {e}")
        sys.exit(1)
