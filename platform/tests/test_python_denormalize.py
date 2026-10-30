"""python 工具的字面 \\n 自愈（_denormalize_code）：治模型双转义混发。

实测样本（2026-10-20 pwn e2e）：代码首字符是真换行、其余全是字面 \\n →
旧的"无真换行才替换"条件被绕过，python -c 语法错误打转 30 轮。
"""
from agents.tools import _denormalize_code


def test_pure_literal_newlines_fixed():
    code = "import socket\\ndef raw():\\n    pass"
    assert _denormalize_code(code) == "import socket\ndef raw():\n    pass"


def test_mixed_real_and_literal_fixed():
    # 真+字面混发：整体编译不过 → 整体替换（旧条件 "\n" not in code 会漏掉这种）
    code = "\nimport socket\\nimport struct\\nwin = 0x401176"
    out = _denormalize_code(code)
    assert "import socket\nimport struct" in out


def test_valid_code_untouched():
    code = "x = 1\ny = 2\nprint(x + y)"
    assert _denormalize_code(code) == code


def test_code_with_legit_backslash_n_string_untouched():
    # 正常代码里合法的 '\\n' 字符串字面量（可编译）不动
    code = "print('a\\\\nb')"
    assert _denormalize_code(code) == code


def test_broken_even_after_fix_stays_original():
    # 替换后也编不过（模型真写错）→ 保持原样，让真实报错透传给模型纠错
    code = "def broken(\\n"
    assert _denormalize_code(code) == code
