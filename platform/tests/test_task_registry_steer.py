"""in-run steer 作用域路由 + 任务级指令日志回归测试。

治两个实证缺陷：
1. 旧广播：定向指令（"专注 xss"）发给全部模块专员，sqli 专员收到与自己使命
   矛盾的指令 → 现在 scope=[modules] 只注入匹配模块的 agent
2. 旧一次性队列：相位间隙积压指令被"第一个"新 agent pop 掉，整批其余拿不到
   → 现在 steer 日志按作用域被每个注册的新 agent 继承（整批全覆盖）
"""
import agents.task_registry as tr


class FakeAgent:
    def __init__(self):
        self.notes = []

    def inject_note(self, text):
        if text and text.strip():
            self.notes.append(text.strip())


def _tid(n=1):
    return f"t-steer-test-{n}"


def setup_function(_):
    # 每个用例干净的全局状态
    tr._ACTIVE_AGENTS.clear()
    tr._AGENT_MODULE.clear()
    tr._STEER_LOG.clear()


def test_global_note_reaches_all_agents():
    tid = _tid(1)
    a_sqli, a_xss, a_root = FakeAgent(), FakeAgent(), FakeAgent()
    tr.register_agent(tid, a_sqli, "sqli")
    tr.register_agent(tid, a_xss, "xss")
    tr.register_agent(tid, a_root, None)  # 任务级 agent（recon 等）
    n = tr.add_note(tid, "简洁点，别过度验证")
    assert n == 3
    for a in (a_sqli, a_xss, a_root):
        assert a.notes == ["简洁点，别过度验证"]


def test_scoped_note_only_reaches_matching_module():
    tid = _tid(2)
    a_sqli, a_xss, a_upload, a_root = FakeAgent(), FakeAgent(), FakeAgent(), FakeAgent()
    tr.register_agent(tid, a_sqli, "sqli")
    tr.register_agent(tid, a_xss, "xss")
    tr.register_agent(tid, a_upload, "upload")
    tr.register_agent(tid, a_root, None)
    n = tr.add_note(tid, "专注 xss，用 DOM 型试试", modules=["xss"])
    assert n == 1
    assert a_xss.notes == ["专注 xss，用 DOM 型试试"]
    assert a_sqli.notes == [] and a_upload.notes == [] and a_root.notes == []


def test_scoped_note_ignores_task_level_agents():
    tid = _tid(3)
    a_root = FakeAgent()
    tr.register_agent(tid, a_root, None)
    n = tr.add_note(tid, "xss 走反射型", modules=["xss"])
    assert n == 0  # 无 xss 专员；任务级 agent 不收定向
    assert a_root.notes == []
    assert len(tr.steer_log(tid)) == 1  # 但日志留痕，等 xss 专员诞生时继承


def test_phase_gap_batch_all_inherit():
    """缺陷 2：相位间隙指令 → 下一批多个子 agent 注册时每个都吃到（不再 first-wins）。"""
    tid = _tid(4)
    n = tr.add_note(tid, "全局：报告一次成文")
    assert n == 0  # 间隙无 agent
    tr.add_note(tid, "xss 重点在评论区", modules=["xss"])
    batch = [FakeAgent() for _ in range(3)]
    tr.register_agent(tid, batch[0], "xss")
    tr.register_agent(tid, batch[1], "sqli")
    tr.register_agent(tid, batch[2], "xss")
    # 两个 xss 专员都吃到全局 + xss 定向；sqli 只吃到全局
    assert batch[0].notes == ["全局：报告一次成文", "xss 重点在评论区"]
    assert batch[1].notes == ["全局：报告一次成文"]
    assert batch[2].notes == ["全局：报告一次成文", "xss 重点在评论区"]


def test_new_agent_inherits_mid_run_steers():
    """后起 agent 继承中途用户意图（如补的情报）。"""
    tid = _tid(5)
    a1 = FakeAgent()
    tr.register_agent(tid, a1, "sqli")
    tr.add_note(tid, "登录凭证 admin/admin123")          # 全局
    tr.add_note(tid, "sqli 走时间盲注", modules=["sqli"])  # 定向
    assert a1.notes == ["登录凭证 admin/admin123", "sqli 走时间盲注"]
    # sqli 结束后 upload 专员后起：继承全局情报，但不吃 sqli 定向
    a2 = FakeAgent()
    tr.register_agent(tid, a2, "upload")
    assert a2.notes == ["登录凭证 admin/admin123"]


def test_log_cap_and_clear():
    tid = _tid(6)
    for i in range(15):
        tr.add_note(tid, f"note-{i}")
    log = tr.steer_log(tid)
    assert len(log) == tr._STEER_LOG_CAP
    assert log[0]["text"] == "note-5" and log[-1]["text"] == "note-14"
    tr.clear(tid)
    assert tr.steer_log(tid) == []
    # 清空后新 agent 不再继承旧指令
    a = FakeAgent()
    tr.register_agent(tid, a, "xss")
    assert a.notes == []


def test_unregister_cancels_future_injection():
    tid = _tid(7)
    a = FakeAgent()
    tr.register_agent(tid, a, "xss")
    tr.unregister_agent(tid, a)
    n = tr.add_note(tid, "别打了", modules=["xss"])
    assert n == 0
    assert a.notes == []
    # 但日志仍留痕（后续若再有 xss 专员诞生会继承）
    assert len(tr.steer_log(tid)) == 1
