# RedBee — AI 渗透智能体（网关 + RED-KB 通用镜像）
#
# 说明：
# - 本镜像同时承载两个服务：PI 网关(:8000) 和 RED-KB(:8001)，用 compose 编排。
# - 网关运行时会**调宿主 Docker daemon 起 Kali 沙箱容器**（兄弟容器模式），
#   因此镜像内置 docker CLI 并在 compose 里挂载宿主 socket /var/run/docker.sock。
# - 运行时密钥**不写入镜像**——通过 compose 的 env_file 注入，见 .dockerignore。

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# ---- 系统依赖 ----
# docker.io：只取 CLI（client），让网关调宿主 daemon 起沙箱
# curl / ca-certificates：健康检查 + 出网
RUN apt-get update && apt-get install -y --no-install-recommends \
        docker.io \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- Python 依赖（先于代码 COPY，充分用 Docker layer 缓存----
COPY platform/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# ---- Playwright 浏览器（browser 工具用）----
RUN playwright install chromium --with-deps

# ---- 平台代码（CWD= /app 保证 from pi_meta.app 等导入成立）----
COPY platform/ /app/

# 网关 8000 / RED-KB 8001
EXPOSE 8000 8001

# 默认起网关；RED-KB 由 compose 的 service 覆盖 command
CMD ["python3", "-m", "uvicorn", "pi_meta.app:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "5"]
