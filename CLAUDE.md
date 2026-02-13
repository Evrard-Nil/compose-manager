# CLAUDE.md

## Project Overview

Docker Compose Manager is a Rust HTTP service that provides remote control over Docker Compose deployments. It fetches compose files directly from GitHub (by tag) and runs docker compose commands.

## Architecture

Single-file Rust application (`src/main.rs`) using:
- **axum** - HTTP framework
- **tokio** - Async runtime
- **reqwest** - GitHub API client + raw file fetching
- **chrono** - Date/time handling for tag age validation

## Key Components

1. **AppState** - Holds configuration (token, owner/repo, work dir) and deployed tag (`RwLock`)
2. **Authentication** - `verify_bearer_token()` validates Authorization header
3. **Handlers** - `compose_up`, `compose_down`, `compose_logs`, `docker_clean`, `docker_ps`, `docker_restart`, `version`
4. **GitHub** - `get_tag_commit_date()` for tag validation, `fetch_github_file()` to download compose files from `raw.githubusercontent.com`
5. **Streaming** - `stream_docker_compose()` streams NDJSON events for compose up/down
6. **Shell commands** - `run_docker_compose()`, `run_command()`, `run_docker_prune()`

## API Endpoints

1. `POST /compose/up {"tag": "v1.0", "file": "docker-compose.yml", "services": [], "env": {}}` — validates tag, fetches file from GitHub, runs `docker compose up -d`. Streams NDJSON events.
2. `POST /compose/down {"tag": "v1.0", "file": "...", "volumes": false, "services": [], "env": {}}` — runs `docker compose down`. Streams NDJSON events.
3. `POST /compose/logs {"file": "...", "tail": 100, "services": []}` — returns compose logs
4. `GET /docker/ps` — returns `docker ps --format json` output
5. `POST /docker/restart {"container": "name-or-id"}` — restarts a container
6. `POST /docker/clean {"volumes": true, "images": true}` — prunes Docker resources
7. `GET /version` — returns currently deployed tag

## Streaming (NDJSON)

`/compose/up` and `/compose/down` stream newline-delimited JSON events:
- `{"event":"stdout","data":"..."}` — stdout line
- `{"event":"stderr","data":"..."}` — stderr line
- `{"event":"done","success":true,"exit_code":0}` — process completed

## Per-request Environment Variables

Compose up/down accept an optional `env` map. Keys must match `[A-Za-z_][A-Za-z0-9_]*`, values must not contain newlines. Written to a temp `.env` file and passed via `--env-file` to docker compose (no shell injection possible).

## Build & Run

```bash
cargo build --release
GITHUB_REPO="..." BEARER_TOKEN="..." ./target/release/compose-manager
```

## Environment Variables

- `GITHUB_REPO` (required) — GitHub repo URL (e.g. `https://github.com/owner/repo`)
- `BEARER_TOKEN` (required) — Auth token for API requests
- `WORK_DIR` (default: `/app/work`) — Directory for downloaded compose files
- `MIN_TAG_AGE_HOURS` (default: `48`) — Minimum tag age; set to `0` for development
- `ENV_FILES` (optional) — Comma-separated list of env file paths passed as `--env-file` flags to all `docker compose` commands (e.g. `ENV_FILES=/etc/app/.env,/etc/app/.env.gpu`)

## CI/CD

GitHub Actions workflow (`.github/workflows/build.yml`) builds a reproducible Docker image using `build-image.sh` and pushes to Docker Hub. Triggers on pushes to `master` (tagged `latest`) and `v*` tags (tagged with version number). Includes artifact attestation via Sigstore.
