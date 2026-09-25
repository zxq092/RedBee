# Troubleshooting

自部署 RedBee 时常见问题排查。面向通用环境；不含内网专属细节。

## 启动问题

### 1. 网关起来了，但报 "All connection attempts failed"
- 确认 RED-KB 是否在监听：`curl -s http://127.0.0.1:8001/health`
- 确认网关 `REDKB_URL` 指向正确的 RED-KB 地址。
  - 本机直跑：`http://127.0.0.1:8001`
  - **Docker Compose 内**：必须是 `http://redkb:8001`（服务名），不能用 `127.0.0.1`
    （容器内 `127.0.0.1` 是它自己的回环，指不到另一个容器）。
- 网关是否绑定 `0.0.0.0`？若只绑回环，外部/容器访问不到。

### 2. 任务派发后秒级返回失败 "目标不可达"
- 引擎会先做可达性预检（3~5s），目标连不上会快速失败，不烧侦察预算。
- 检查目标地址/端口/网络。若目标是容器/靶场，确认它在网关与沙箱都能访问的网络上。
- 沙箱（`inhouse-sess-*`）由宿主 Docker daemon 以 `--network bridge` 创建：
  - 目标必须在**宿主能访问**的网络（如宿主 docker bridge），沙箱才能打到。
  - 如果目标只在某个自定义 compose 网络里，沙箱默认连不到——把目标放到宿主可见网络。

### 3. 网关重启后 kill 不掉 / 停不下来
- Web UI 用 SSE(`/stream`)长连接；优雅停机会被长连接卡住。
- 启动网关务必带 `--timeout-graceful-shutdown 5`（`run.sh`/`start_pimeta.sh` 已内置）。

## 沙箱 / Docker

### 4. 沙箱容器起不来 / 攻击命令失败
- 确认宿主有 `vxcontrol/kali-linux:latest` 镜像：`docker pull vxcontrol/kali-linux:latest`
  （或设 `HINSE_DOCKER_IMAGE` 指向你自己的镜像）。
- 网关容器必须能访问宿主 Docker：
  - 挂载 socket：compose 里 `- /var/run/docker.sock:/var/run/docker.sock`
  - 镜像内置 docker CLI。
- 若"容器内没有 Docker daemon"，这是正常的——它走宿主 daemon（兄弟容器模式），不是嵌套 daemon。

### 5. 本机构建镜像时 `apt-get`/`pip` 连不上外网
- 检查宿主是不是被 Kubernetes/CNI 网络层限制了**容器出网**（宿主能 curl 外网、容器内不行）。
- 这种情况 build/push 镜像走 **GitHub Actions**（CI 网络正常）即可，见 `.github/workflows/ci.yml`。

## LLM / 性能

### 6. 任务很慢 / LLM 调用挂死
- **并发是常见根因**：多任务并行 + 大上下文会让单点 LLM 超时挂死。
  - 调低 `PIMETA_GLOBAL_MAX_LLM_CONCURRENCY`（全平台闸门）和 `PIMETA_MAX_PARALLEL`（单任务并行）。
- **超时配置**：非流式聚合下 `MODEL_READ_TIMEOUT` 要覆盖整段生成（大上下文可能几十秒），
  默认 30s 在大任务上会误超时。可调大（如 240s）+ `MODEL_TIMEOUT` 同步。
- 看网关日志里的 `[llm] ... el=`（单次调用耗时）判断是慢还是挂。

### 7. 模型 "all available model runtimes failed"
- 检查 `MODEL_PRIORITY` 里每个模型的端点/key 是否可用；`curl` 直连验证。
- 首选挂了会自动降级到备用；若都失败会记 `runtime_error`，任务记录里会显示原因。

## 知识库

### 8. `kb_query` 查不到东西 / 检索结果不对
- RED-KB 有治理门禁，只有 `active` 的条目才被检索到。刚 `ingest` 且未 verified 的条目不会进检索。
- `EMBEDDING_URL` 未配置时退化为关键词检索，语义召回会差。
- 想让某条可检索，ingest 时设 `source_type=inhouse` + `verified` + 对应治理字段
  （见 `redkb/governance.py` 的 `governance_status_for_entry`）。

## Docker Compose 常见

### 9. `docker compose up` 拉取失败 / 跑不起来
- 拉取镜像：`docker compose --profile sandbox pull`（预拉 Kali 沙箱镜像）。
- 先 `cp platform/config.example.env platform/.env` 并填真实 LLM key，否则网关无模型可用。
- compose 里 `REDKB_URL=http://redkb:8001`、挂 `docker.sock`、`data` 卷到 `/data`——按仓库内
  `docker-compose.yml` 即可，不要手动改成 `127.0.0.1` 或去掉 socket。
