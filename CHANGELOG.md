# Changelog

本项目遵循 [Semantic Versioning](https://semver.org/)。

## [0.1.0] - 2026-09-25

首个开源发布（Initial open-source release）。

### 加入（Added）
- **RedBee 自研 AI 渗透引擎**：给定目标自动侦察、利用、出带 PoC/证据的报告。
- **知识回流闭环（核心卖点）**：每次渗透成功经验按漏洞类自动蒸馏进 RED-KB 知识库，
  下次同类目标更快更准 —— `自动查 KB → 渗透 → submit_finding → 蒸馏 → 回流 → 热启动`。
- **5 阶段受控编排**：`pre_recon(KB情报) → recon → root-decide(动态派模块) → exploit(并行子agent) → report`。
- **172 个技能包 + 种子知识库**：冷启动即有可用的渗透知识。
- **63 个工具 + OpenAI function calling**：结构化调用，不靠模型输出 JSON 文本。
- **模型路由 + 自动降级**：首选挂自动切备用（`.env` 配置）。
- **Docker/Compose + GitHub Actions 多架构发布**：打 `v*` tag 自动构建并推 GHCR。

### Web UI
- 明暗主题（跟随系统自动切换）。
- 中英双语切换（核心 UI；动态长文暂回退中文）。
- 执行中动态状态栏（opencode 风格方块 loading + 相位/耗时/活动提示）。
- 会话级高级参数持久化。
- 任务记录显示时间段（今天 HH:MM – HH:MM）与中文耗时。

### 修复（Fixed）
- 历史任务的 `running` 状态在网关重启后不再误判为"执行中"（孤儿任务按 `interrupted` 处理）。
- 语言切换取词层级错误（`TRANS` 顶层 vs `{zh,en}` 子层）导致切换无效。

### 安全（Security）
- `.env` 与密钥不入库、不入镜像；运行时经 compose `env_file` 注入。

[0.1.0]: https://github.com/<your-org>/<repo>/releases/tag/v0.1.0
