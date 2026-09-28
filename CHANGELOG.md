# Changelog

本项目遵循 [Semantic Versioning](https://semver.org/) / This project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-09-25

- Initial open-source release.
- Multi-agent controlled orchestration: 5-phase pipeline (KB hot-start → recon → root-decide → parallel exploit → governed findings), per-task budgets, deterministic tool executors, cross-agent vulnerability board with re-proof and skip logic, KB-first design with automatic knowledge reflux.
- 172 curated security skills (vulnerabilities / cloud / enterprise / LLM / methodology / reporting ...), loaded on demand.
- Web console (task dispatch, live board, session history), REST API, Docker + docker-compose deployment.
