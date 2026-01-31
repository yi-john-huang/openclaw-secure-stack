# Project Structure

## Directory Organization
```
openclaw-secure-stack/
├── src/                          # Source code
│   ├── models.py                 # Shared Pydantic data models (enums, findings, events)
│   ├── audit/
│   │   └── logger.py             # Append-only JSON Lines audit logger
│   ├── proxy/
│   │   ├── auth_middleware.py     # ASGI Bearer token auth middleware
│   │   └── app.py                # FastAPI reverse proxy with body sanitization
│   ├── scanner/
│   │   ├── scanner.py            # Core scanner engine (rule loading, file scanning)
│   │   ├── cli.py                # Click CLI for scan/quarantine commands
│   │   ├── trust_score.py        # Trust score computation
│   │   └── rules/
│   │       ├── dangerous_api.py  # AST rule: eval, Function, child_process
│   │       ├── network_exfil.py  # AST rule: fetch, XMLHttpRequest, http/https
│   │       └── fs_abuse.py       # AST rule: writeFile, unlink, rmSync
│   ├── quarantine/
│   │   ├── db.py                 # SQLite quarantine database
│   │   └── manager.py            # Quarantine lifecycle (quarantine, override, rescan)
│   └── sanitizer/
│       └── sanitizer.py          # Prompt injection detection and stripping
├── config/
│   ├── scanner-rules.json        # Scanner rule definitions
│   ├── prompt-rules.json         # Prompt injection regex rules
│   └── egress-allowlist.conf     # Allowed external domains
├── docker/
│   └── egress/
│       ├── Corefile              # CoreDNS configuration
│       ├── Dockerfile            # CoreDNS sidecar image
│       └── generate-zone.sh      # Allowlist → zone file converter
├── tests/
│   ├── conftest.py               # Shared test fixtures
│   ├── unit/                     # Unit tests (70% of suite)
│   ├── integration/              # Integration tests (20% of suite)
│   └── security/                 # Security/adversarial test suite (10%)
├── .spec/                        # SDD workflow files
│   ├── steering/                 # Project steering documents
│   └── specs/                    # Feature specifications
├── Dockerfile                    # Multi-stage build (distroless runtime)
├── docker-compose.yml            # Orchestration with security hardening
├── install.sh                    # One-click deployment script
├── pyproject.toml                # Project config and dependencies
├── .env.example                  # Environment variable template
└── .gitignore
```

## Key Directories
- **src/proxy/**: Reverse proxy layer — auth + request forwarding + body sanitization
- **src/scanner/**: Static analysis engine — AST rules + pattern matching + CLI
- **src/quarantine/**: Quarantine lifecycle — SQLite state + file management
- **src/sanitizer/**: Prompt injection detection — regex rules with strip/reject
- **src/audit/**: Security event logging — append-only JSON Lines
- **config/**: Runtime configuration files (rules, allowlists)
- **docker/**: Container infrastructure (CoreDNS egress sidecar)

## Code Organization Patterns
- **Layered architecture**: proxy → sanitizer → upstream; scanner → quarantine → audit
- **Dependency injection**: components accept `audit_logger` parameter, None = no logging
- **Immutable models**: Pydantic `frozen=True` for all data models
- **Fail-closed**: missing config raises exceptions rather than allowing all

## File Naming Conventions
- **Source files**: snake_case.py (e.g., `auth_middleware.py`)
- **Test files**: test_<module>.py (e.g., `test_auth_middleware.py`)
- **Configuration**: kebab-case.json/conf (e.g., `scanner-rules.json`)
- **Constants**: UPPER_SNAKE_CASE
- **Functions/Variables**: snake_case
- **Classes**: PascalCase
- **Enums**: PascalCase with UPPER_SNAKE_CASE members

## Architectural Principles
- **Sidecar pattern**: Security stack wraps OpenClaw without modification
- **Separation of concerns**: Each module handles one security domain
- **Defense in depth**: Multiple independent security layers
- **Fail-closed**: Deny by default on missing or invalid configuration
- **Auditability**: Every security-relevant action produces an audit event
