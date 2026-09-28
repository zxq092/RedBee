# 📚 RedBee Skills

## 🎯 Overview

A library of **172 curated security skills** — specialized knowledge packages that give the RedBee agent deep expertise in specific vulnerability classes, technologies, and testing methodologies. Each skill provides advanced techniques, practical examples, and validation methods that go beyond baseline security knowledge.

Skills are loaded **on demand** via the `list_skills` / `load_skill` tools (Strix-native skill architecture — see [PROVENANCE.md](PROVENANCE.md) for origins and licensing), and the orchestrator also auto-injects the skill focused on the current attack module into the agent's initial context.

---

## 🏗️ Architecture

### How Skills Work

1. **Focused injection**: when an exploit agent for module `sqli` starts, the matching skill (e.g. `sql-injection`) is injected into its initial messages — the agent begins with the right playbook, not generic advice.
2. **On-demand loading**: mid-run, the agent can call `list_skills` (browse the library) and `load_skill <name>` to pull in expertise it needs (e.g. `jwt-tampering` while working an authz bug).

Skill content is plain Markdown with YAML frontmatter (`name`, `description`), so the library is easy to read, extend, and audit.

---

## 📁 Skill Categories

| Category | Count | Purpose |
|----------|-------|---------|
| `vulnerabilities` | 87 | Core vulnerability classes: injection, XSS, auth bypass, business logic, race conditions, parser/representation mismatches, agent/LLM security |
| `shannon` | 15 | Phased exploit workflows (recon → pre-recon-code → exploit-* → vuln-* → report) distilled from Shannon's worker prompts |
| `tooling` | 13 | Command-line playbooks for core sandbox tools (nmap, nuclei, httpx, ffuf, subfinder, naabu, katana, sqlmap, ...) |
| `enterprise` | 10 | Enterprise attack surface: Microsoft 365, Okta, vCenter, identity and on-prem cloud |
| `reconnaissance` | 8 | Advanced information gathering and enumeration for attack-surface mapping |
| `technologies` | 7 | Third-party services and stacks: Supabase, Firebase, Auth0, payment gateways, Electron, **LLM applications (OWASP LLM Top 10)** |
| `reporting` | 5 | Triage gates, evidence standards, report structure |
| `analysis` | 4 | Counter-evidence, fix verification, severity calibration, source-aware discovery |
| `cloud` | 4 | AWS, Azure, GCP, Kubernetes security testing |
| `frameworks` | 4 | Framework-specific testing (Django, Express, FastAPI, Next.js) |
| `methodology` | 4 | Red-team methodology and hunt frameworks |
| `scan_modes` | 4 | Scan-mode playbooks (authenticated, unauthenticated, API, source-aware) |
| `custom` | 4 | Specialized scenarios: API spec testing, dependency CVE scanning, npx/package-runner confusion, source-aware SAST |
| `coordination` | 2 | Multi-agent coordination playbooks (root agent, whitebox orchestration) |
| `protocols` | 2 | Protocol-specific patterns: GraphQL, WebSocket, OAuth |

Notable skills:
- `llm_applications` (technologies): end-to-end OWASP LLM Top 10 coverage across models, RAG, vectors, agents, tools, outputs, supply chain, and resource controls
- `llm_prompt_injection` (vulnerabilities): direct, indirect, multimodal, memory, and tool-result prompt-injection testing
- `agentic_system_security` (vulnerabilities): effective-authority and MCP/tool ecosystem security testing
- `browser_security` (vulnerabilities): browsing-context, postMessage, XS-Leaks, service-worker, and cross-origin state-machine testing
- `semantic_confusion` (vulnerabilities): cross-boundary parser, normalization, and representation mismatch analysis
- `argument_injection` (vulnerabilities): shell-free CLI option smuggling and argv transformation boundaries
- `source_aware_whitebox` (coordination): white-box orchestration playbook
- `source_aware_sast` (custom): semgrep/AST/secrets/supply-chain static triage workflow

---

## 🎨 Creating New Skills

A good skill is a structured knowledge package that typically includes:

- **Advanced techniques** - Non-obvious methods specific to the task and domain
- **Practical examples** - Working payloads, commands, or test cases with variations
- **Validation methods** - How to confirm findings and avoid false positives
- **Context-specific insights** - Environment and version nuances, configuration-dependent behavior, and edge cases
- **YAML frontmatter** - `name` and `description` fields for skill metadata

Drop the Markdown file into the matching category directory. No code changes needed — `list_skills` picks it up from the filesystem.

---

## 🤝 Contributing

Community contributions are welcome — contribute new skills via pull request. Keep skills general (portable across targets), include validation criteria, and credit upstream sources in [PROVENANCE.md](PROVENANCE.md).
