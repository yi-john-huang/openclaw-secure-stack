# Technology Stack

## Architecture
**Type**: Sidecar / Reverse Proxy
**Language**: Python 3.12+
**Module System**: Standard Python packages
**Framework**: FastAPI (async ASGI)
**Build Tool**: Hatchling + uv

## Core Technologies
- **Runtime**: Python 3.12+ (CPython)
- **Language**: Python with type annotations
- **Framework**: FastAPI + Starlette (ASGI middleware)
- **Testing**: pytest + pytest-asyncio + pytest-cov
- **Parsing**: tree-sitter + tree-sitter-javascript (AST analysis)
- **HTTP Client**: httpx (async proxy forwarding)
- **Data Validation**: Pydantic v2 (frozen models)
- **Database**: SQLite via stdlib sqlite3 (quarantine state)
- **CLI**: Click (scanner/quarantine CLI)
- **DNS Filtering**: CoreDNS (egress sidecar)

## Development Environment
- **Runtime Version**: Python >= 3.12
- **Package Manager**: uv (fast Python package manager)
- **Testing Framework**: pytest
- **Linting**: ruff

## Dependencies
### Production Dependencies
- `fastapi` — ASGI web framework
- `uvicorn` — ASGI server
- `httpx` — async HTTP client for proxying
- `pydantic>=2.0` — data models with validation
- `click` — CLI framework
- `tree-sitter` — incremental parsing library
- `tree-sitter-javascript` — JavaScript grammar for tree-sitter
- `tree-sitter-typescript` — TypeScript grammar for tree-sitter

### Development Dependencies
- `pytest` + `pytest-asyncio` + `pytest-cov` — testing
- `ruff` — linting and formatting
- `mypy` — static type checking
- `pytest-httpx` — httpx mocking

## Development Commands
```bash
# Install dependencies
uv sync

# Run all tests
uv run pytest tests/ -q

# Run tests with coverage
uv run pytest tests/ --cov=src --cov-report=term-missing

# Lint
uv run ruff check src/ tests/

# Lint with auto-fix
uv run ruff check --fix src/ tests/

# Type check
uv run mypy src/

# Run scanner CLI
uv run python -m src.scanner.cli scan <skill-path>

# Start proxy server (dev)
uv run uvicorn src.proxy.app:create_app --factory --reload
```

## Quality Assurance
- **Linting**: ruff (line-length 100, Python 3.12 target)
- **Type Checking**: mypy with strict mode
- **Testing**: 112 tests across unit, integration, and security suites
- **Security**: OWASP Top 10 aligned, constant-time comparisons, no hardcoded secrets

## Deployment Configuration
- **Containerization**: Docker with multi-stage build (distroless Python runtime)
- **Orchestration**: Docker Compose with security hardening
- **Build Process**: `docker compose build` or `install.sh`
- **Security Hardening**: read-only filesystem, dropped capabilities, non-root user, internal network
