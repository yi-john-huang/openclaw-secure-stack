# Project Structure

## Directory Layout
```text
openclaw-secure-stack/
|-- src/
|   |-- proxy/              # FastAPI app, auth middleware, governance helpers, webhook handlers
|   |   |-- governance_helpers.py  # evaluate_governance(), has_tool_calls(), strip_headers()
|   |   `-- governance_routes.py   # /governance/* REST endpoints (plans, approvals)
|   |-- webhook/            # Telegram/WhatsApp relay pipeline
|   |   |-- models.py       # WebhookMessage, WebhookResponse
|   |   `-- relay.py        # WebhookRelayPipeline (sanitize → governance → quarantine → forward → scan)
|   |-- sanitizer/          # Prompt injection strip/reject logic
|   |-- scanner/            # AST scanner engine, CLI, trust scoring, rule implementations
|   |   `-- rules/          # Rule modules by detection category (base.py = abstract base class)
|   |-- quarantine/         # SQLite persistence + quarantine manager
|   |-- governance/         # Intent classifier, planner, validator, approver, enforcer, session/store
|   |   `-- middleware.py   # GovernanceMiddleware integration for proxy and webhook pipelines
|   |-- audit/              # JSONL append-only logger
|   `-- models.py           # Shared Pydantic models
|-- tests/
|   |-- unit/               # Module-level tests
|   |-- integration/        # Cross-module behavior tests
|   `-- security/           # Adversarial and abuse-path tests
|-- config/                 # JSON policy/rule files and network allowlist inputs
|-- docs/                   # User and developer quickstarts
|-- scripts/                # Operational scripts (e.g., audit)
|-- docker/                 # CoreDNS and Caddy runtime config
|-- plugins/prompt-guard/   # OpenClaw plugin hook (TypeScript)
|-- .spec/
|   |-- steering/           # Project steering context docs
|   `-- specs/              # SDD feature specifications
|-- pyproject.toml          # Python project metadata and tool config
|-- docker-compose.yml      # Service topology and hardening options
|-- Dockerfile              # Container image build for secure-stack proxy
|-- build.sh                # Build automation script
|-- install.sh              # Installation helper script
|-- .env.example            # Environment variable template
|-- CHANGELOG.md            # Release history
`-- README.md
```

## Naming Conventions

### Files
| Type | Convention | Example |
|------|------------|---------|
| Python modules | `snake_case.py` | `auth_middleware.py` |
| Package markers | `__init__.py` | `src/scanner/__init__.py` |
| Tests | `test_<subject>.py` | `test_auth_middleware.py` |
| Config | kebab-case JSON/conf | `scanner-rules.json` |
| Scripts | `snake_case.py` | `audit.py` |

### Code
| Element | Convention | Example |
|---------|------------|---------|
| Classes / Pydantic models | PascalCase | `ScanFinding` |
| Functions / methods / vars | snake_case | `create_app_from_env` |
| Constants | UPPER_SNAKE_CASE | `OPENCLAW_TOKEN` |
| Module-private helpers | leading underscore where useful | `_load_rules` |

## Module Organization Rules
- Keep security concerns separated by domain (`auth`, `sanitizer`, `scanner`, `governance`, `webhook`, `audit`).
- Share cross-module schemas only through `src/models.py`, governance-local models in `src/governance/models.py`, and webhook models in `src/webhook/models.py`.
- Place scanner detection logic under `src/scanner/rules/`; keep CLI orchestration in `src/scanner/cli.py`.
- Keep persistence abstractions close to their domain (`quarantine/db.py`, `governance/db.py`, `governance/store.py`).

## Import and Dependency Patterns
1. Standard library imports
2. Third-party imports
3. `src` package imports
4. Relative imports only when local clarity is improved

Prefer explicit imports and avoid circular dependencies between core modules.

## Testing Structure
- `tests/unit/`: deterministic, fast tests for single modules/classes.
- `tests/integration/`: request/response and component interaction coverage.
- `tests/security/`: malicious skill and abuse scenarios.

When adding functionality, add or update tests in the matching suite first; keep security-sensitive logic covered by explicit adversarial cases.

## Configuration and Policy Files
- `config/scanner-rules.json`: scanner rule metadata and patterns
- `config/prompt-rules.json`: prompt injection detection rules
- `config/indirect-injection-rules.json`: tool-result injection rules
- `config/governance-policies.json`: governance validation policy
- `config/intent-patterns.json`: intent classifier patterns
- `config/egress-allowlist.conf`: DNS allowlist for outbound network access
- `config/skill-pins.json`: skill integrity pins for trust verification
- `config/quarantine-list.json`: seed quarantine list (bind-mounted into containers)

Treat `config/` as policy-as-code: prefer data-driven changes there before hardcoding behavior.

## Architectural Principles

These principles guide all design and implementation decisions:

1. **Fail-closed defaults** — When a security decision is ambiguous or a component errors, deny the operation. No request should pass through silently on failure.
2. **Sidecar pattern** — The secure stack wraps upstream OpenClaw without patching it. All security controls live outside the upstream codebase and can be updated independently.
3. **Separation of concerns by security domain** — Each module owns a single security responsibility (auth, sanitization, scanning, governance, audit). Cross-cutting behavior is composed at the proxy/middleware layer, not embedded in individual modules.
4. **Defense-in-depth** — Multiple overlapping controls (authentication, input sanitization, governance validation, network isolation) ensure that no single bypass compromises the system.
5. **Auditability guarantee** — Every security-relevant decision (allow, deny, quarantine, governance override) is recorded in the append-only audit log. Silent drops are treated as bugs.
