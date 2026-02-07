# Technology Overview

## Stack

### Language
- **Primary:** Python
- **Version:** 3.12+
- **Runtime:** CPython with ASGI server for API path

### Frameworks and Libraries
- **FastAPI**: Reverse proxy HTTP API and middleware composition
- **Uvicorn**: ASGI server for local and container runtime
- **Pydantic v2**: Data models and validation
- **HTTPX**: Upstream HTTP forwarding and integration points
- **Click**: Scanner CLI commands
- **tree-sitter + JS/TS grammars**: AST parsing for skill analysis

### Build System
- **Hatchling**: PEP 517 build backend (configured in `pyproject.toml`)

### Supporting Tech
- **Docker / Docker Compose**: Deployment and network isolation
- **SQLite**: Quarantine state and governance persistence
- **CoreDNS**: DNS forwarding with allowlist policy
- **Caddy**: HTTPS edge for control UI
- **TypeScript plugin**: `plugins/prompt-guard` hook for tool-result sanitization

## Architecture

### Pattern
Security wrapper around an unmodified upstream service, with modular security components and policy-driven governance.

### Runtime Flow
```text
API Client -> Proxy (auth → sanitizer → governance → forward) -> OpenClaw
                                    |
                                    +-> Audit logger

Webhook (Telegram/WhatsApp) -> Proxy (signature → rate limit → replay →
    sanitize → governance → quarantine → forward → response scan) -> OpenClaw
                                    |
                                    +-> Audit logger

Plugin Hook (inside OpenClaw):
Tool result -> prompt-guard plugin (indirect injection scan) -> sanitized result

Offline/administrative flow:
Skill file -> Scanner (AST rules) -> Quarantine manager (SQLite)
```

### Logical Modules
- `proxy`: FastAPI app, auth middleware, governance helpers, webhook handlers
- `webhook`: Telegram/WhatsApp relay pipeline (sanitize → governance → quarantine → forward → scan)
- `sanitizer`: Prompt injection rules engine
- `governance`: Intent classification, planning, validation, approval, enforcement, session/store
- `governance/middleware`: GovernanceMiddleware for proxy and webhook pipelines
- `scanner`: AST scanning engine, trust scoring, CLI
- `quarantine`: Persistence and lifecycle for blocked skills
- `audit`: Append-only JSONL security events

## Development Environment

### Prerequisites
- Python 3.12+
- `uv` package/runtime manager
- Docker 20.10+ and Docker Compose v2+ for containerized stack

### Setup
```bash
uv sync
uv run pytest tests/ -q
uv run uvicorn src.proxy.app:create_app_from_env --factory --reload
```

### Common Commands
| Command | Purpose |
|---------|---------|
| `uv sync` | Install project and dev dependencies |
| `uv run pytest tests/ -q` | Run full test suite |
| `uv run ruff check src/ tests/` | Lint code |
| `uv run mypy src/` | Type checking |
| `uv run python -m src.scanner.cli scan <file>` | Scan a JS/TS skill |
| `openclaw-scanner scan <file>` | Scan via installed CLI entry point |
| `python scripts/audit.py` | Run security posture audit |
| `docker compose up -d --build` | Build and start stack |

## Quality Standards
- Coverage gate configured at **90%** (`tool.coverage.report.fail_under`)
- Linting via Ruff (`E,F,W,I,N,UP,B,SIM` rulesets)
- Strict mypy mode enabled for `src/`
- Tests organized into unit, integration, and security suites

## Dependency Baseline

### Production Dependencies
- `fastapi`, `uvicorn[standard]`, `httpx`, `pydantic`, `click`
- `tree-sitter`, `tree-sitter-javascript`, `tree-sitter-typescript`

### Development Dependencies
- `pytest`, `pytest-asyncio`, `pytest-cov`, `pytest-httpx`
- `ruff`, `mypy`

## Deployment Notes
- Containerized runtime with hardened defaults (read-only FS, non-root, dropped capabilities, no-new-privileges)
- Network segmentation via Docker networks; OpenClaw not exposed directly by default
- DNS egress constrained by allowlist configuration in `config/egress-allowlist.conf`
- Skill integrity pins defined in `config/skill-pins.json`
