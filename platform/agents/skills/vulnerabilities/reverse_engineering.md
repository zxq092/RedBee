---
name: reverse-engineering
description: CTF/offline reversing — static analysis of a binary/script to understand logic and recover the flag or a condition.
---

# Reverse Engineering (offline artefact)

Use when the flag is hidden in program logic (a binary, a packed/compiled challenge, a
JavaScript/other script, a crackme) rather than a web endpoint or cipher only.

## Workflow
1. Recon: `file` (arch/flag), `strings` (look for flag parts / format strings / hints),
   `checksec`/`readelf -h` (PIE/NX/relic).
2. Static analysis:
   - `objdump -d` / `readelf -s` for symbols and disassembly of key functions.
   - Python/JS challenges: read the source directly, follow the flag-check logic.
   - If packed: `strings` after entropy check; unpack known packers (upx) if present.
3. Reconstruct the check: identify what input produces the flag (a condition on chars,
   an XOR key, a hash of a known word). Script it with python to recover the flag.
4. If a binary/service: you may need the pwn domain tools (native_gdb/run) to trigger it.

## Confirmation
- The flag is recovered by running a reconstruction script (python) and capturing output.
  Never fabricate; evidence = the script + recovered flag.
