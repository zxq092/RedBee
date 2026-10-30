# Skill Library Provenance

The skills in this directory are distilled from Strix's `strix/skills/` (AGPLv3, see `LICENSE`),
preserving the original directory layout (vulnerabilities / reconnaissance / analysis / tooling / ...).

Purpose: the RedBee agent loads them on demand via the `list_skills` / `load_skill` tools
(Strix-native skill architecture).

---

# Skill 库来源

本目录的 skill 内容蒸馏自 Strix（AGPLv3，见 `LICENSE`）`strix/skills/`，
按原目录结构（vulnerabilities/reconnaissance/analysis/tooling/...）保留。
用途：RedBee agent 经 `list_skills` / `load_skill` 工具按需加载（Strix 原生 skill 架构）。

---

## Additional sources / 追加来源

### 1. Claude-BugHunter (2026-09-16)
`clown-src-6k-skill` — 83 skills distilled from H1 disclosed reports.
License: CC BY 4.0 / MIT (per upstream). Files: `hunt-*`, `enterprise/`, `methodology/bb-*`, `reporting/triage*`.
Distiller: `/tmp/opencode/distill_cbh.py`.

### 2. mukul975/Anthropic-Cybersecurity-Skills (2026-10-29)
https://github.com/mukul975/Anthropic-Cybersecurity-Skills — **Apache-2.0**.
24 skills distilled for the OT/ICS (电力/工控) and routing/network domains.
Upstream `scripts/` and `references/` are NOT bundled; equivalent capability uses the sandbox
CLI (pymodbus / snmpwalk / scapy / nmap NSE / tshark).
Files: `vulnerabilities/ot-*.md`, `vulnerabilities/net-*.md`, `protocols/net-*.md`, `tooling/net-*.md`.
Each file carries the upstream skill name and source URL in its header/footer.
Distiller: `/tmp/opencode/distill_mk.py`. Mapping list lives in that script.
NOTICE: Apache-2.0 requires attribution — the per-file header/footer satisfies it.

### 3. Hand-written (2026-10-29)
`vulnerabilities/ot-ics-security.md`, `protocols/routing-protocols.md`,
`protocols/network-infrastructure.md` — written in-house, tuned to this platform's
tools and sandbox (no upstream license).
