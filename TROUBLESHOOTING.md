# Troubleshooting

[English](TROUBLESHOOTING.md) | [简体中文](TROUBLESHOOTING.zh-CN.md)

Common issues when self-deploying RedBee. Written for generic environments; no internal-network specifics.

## Startup

### 1. Gateway is up but logs "All connection attempts failed"
- Confirm RED-KB is listening: `curl -s http://127.0.0.1:8001/health`
- Confirm the gateway's `REDKB_URL` points at the right RED-KB address:
  - Running on the host directly: `http://127.0.0.1:8001`
  - **Inside Docker Compose**: it must be `http://redkb:8001` (the service name). `127.0.0.1`
    inside a container is the container's own loopback and cannot reach another service.
- Is the gateway bound to `0.0.0.0`? If it only binds loopback, external/container clients can't reach it.

### 2. A task fails within seconds with "target unreachable"
- The engine does a reachability pre-check first (3~5s); an unreachable target fails fast instead of burning recon budget.
- Check the target address/port/network. If the target is a container/range, make sure it sits on a network reachable from both the gateway and the sandbox.
- Sandboxes (`inhouse-sess-*`) are created by the **host** Docker daemon with `--network bridge`:
  - The target must be on a network the **host can reach** (e.g. the host docker bridge) or the sandbox can't hit it.
  - If the target only exists on a custom compose network, the sandbox can't reach it by default — put the target on a host-visible network.

### 3. Gateway won't stop after restart / kill
- The Web UI uses SSE (`/stream`) long-lived connections; graceful shutdown can be held open by them.
- Always start the gateway with `--timeout-graceful-shutdown 5` (already built into `run.sh` / `start_pimeta.sh`).

## Sandbox / Docker

### 4. Sandbox container won't start / attack commands fail
- Confirm the host has the sandbox image `redbee-kali:local` (build per the README: `docker build -f Dockerfile.kali -t redbee-kali:local .`),
  or point `HINSE_DOCKER_IMAGE` at your own working Kali image.
- The gateway container must be able to reach the host Docker daemon:
  - Mount the socket: `- /var/run/docker.sock:/var/run/docker.sock` in compose
  - The platform image ships the docker CLI.
- "No Docker daemon inside the container" is expected — it talks to the **host** daemon (sibling-container mode), not a nested daemon.

### 5. `apt-get`/`pip` can't reach the internet while building images locally
- Check whether the host's Kubernetes/CNI network layer blocks **egress from containers** (host can curl the internet, containers cannot).
- In that case, build/push images via **GitHub Actions** (CI has normal network), see `.github/workflows/ci.yml`.

## LLM / Performance

### 6. Tasks are very slow / LLM calls hang
- **Concurrency is the usual root cause**: parallel tasks + large contexts can time out and hang a single LLM endpoint.
  - Lower `PIMETA_GLOBAL_MAX_LLM_CONCURRENCY` (platform-wide gate) and `PIMETA_MAX_PARALLEL` (per-task parallelism).
- **Timeouts**: with non-streaming aggregation, `MODEL_READ_TIMEOUT` must cover the *entire* generation (large contexts can take tens of seconds).
  The default 30s will false-timeout on big tasks. Raise it (e.g. 240s) and keep `MODEL_TIMEOUT` in sync.
- Watch `[llm] ... el=` in the gateway log (per-call elapsed) to tell "slow" from "hung".

### 7. Model error "all available model runtimes failed"
- Check that each model in `MODEL_PRIORITY` has a reachable endpoint/valid key; verify with a direct `curl`.
- If the primary fails it auto-falls back to the backup; if all fail a `runtime_error` is recorded and the task record shows the reason.

## Knowledge Base

### 8. `kb_query` returns nothing / wrong results
- RED-KB has a governance gate: only `active` entries are searchable. Freshly ingested, unverified entries are not in the index.
- Without `EMBEDDING_URL` configured, search degrades to keyword matching and semantic recall suffers.
- To make an entry searchable, ingest with `source_type=inhouse` + `verified` + the matching governance fields
  (see `governance_status_for_entry` in `redkb/governance.py`).

## Docker Compose

### 9. `docker compose up` pull fails / won't run
- Pre-pull the sandbox image: `docker compose --profile sandbox pull`
- First `cp platform/config.example.env platform/.env` and fill in real LLM keys, or the gateway has no model to use.
- Compose wires `REDKB_URL=http://redkb:8001`, mounts `docker.sock`, and maps the `data` volume to `/data` — just use the repo's `docker-compose.yml` as-is; don't hand-edit it to `127.0.0.1` or drop the socket.
