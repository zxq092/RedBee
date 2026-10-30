"""python 工具 shell 命令构造：多行代码必须能跑（json.dumps 的老 bug）。

2026-10-30 实测：`f"python3 -c {json.dumps(code)}"` 把真换行转成 \\n 转义串，
bash 双引号不还原 → python 收到字面反斜杠+n → SyntaxError（所有多行代码全军覆没，
历史上曾被误诊为"模型多行参数序列化失败"）。改用 shlex.quote 保留真换行。
"""
import subprocess

from agents.tools import _python_cmd


def _run(code: str) -> str:
    r = subprocess.run(["bash", "-c", _python_cmd(code)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_multiline_real_newlines_runs():
    assert _run("import json\nx = [1, 2]\nprint(json.dumps(x))") == "[1, 2]"


def test_literal_backslash_n_is_denormalized():
    assert _run("import json\\nx = [1, 2]\\nprint(json.dumps(x))") == "[1, 2]"


def test_single_quotes_and_specials_survive_shell():
    out = _run("s = \"it's $(whoami) `id` ; | &\"\nprint(s)")
    assert out == "it's $(whoami) `id` ; | &"


def test_no_escaped_newline_leaks_into_command():
    cmd = _python_cmd("a = 1\nb = 2\nprint(a + b)")
    assert "\\n" not in cmd
    assert "\n" in cmd


def test_code_as_list_of_lines_is_joined():
    from agents.tools import _denormalize_code
    assert _denormalize_code(["import json", "print(json.dumps(1))"]) == 'import json\nprint(json.dumps(1))'


def test_code_as_nested_object_is_unwrapped():
    from agents.tools import _denormalize_code
    assert _denormalize_code({"code": "print(7)"}) == "print(7)"


def test_code_none_does_not_raise():
    from agents.tools import _denormalize_code
    assert _denormalize_code(None) == ""


def test_registered_python_tool_is_async_and_sandboxed():
    """守卫：装饰器必须贴在 async tool_python 上（曾被 _python_cmd 顶替 → await str 崩）。"""
    import inspect
    from agents.tools import get_tool
    d = get_tool("python")
    assert inspect.iscoroutinefunction(d.handler)
    assert list(inspect.signature(d.handler).parameters) == ["code", "container", "workdir"]
    assert "sandbox" in d.description.lower()
