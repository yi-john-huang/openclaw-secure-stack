# OpenClaw Secure Stack

A hardened deployment wrapper that makes OpenClaw safe to self-host. Wraps an unmodified OpenClaw instance with authentication, skill scanning, prompt injection mitigation, network isolation, and full audit logging — without changing a single line of OpenClaw code.

## Why This Exists

OpenClaw is a powerful AI agent that can install and run third-party "skills" (JavaScript/TypeScript plugins). Running it on your infrastructure introduces real risks:

| Risk | What could happen | How we stop it |
|------|-------------------|----------------|
| **Malicious skills** | A skill runs dynamic code, spawns child processes, or exfiltrates data | AST-based scanner detects dangerous patterns before skills execute |
| **Prompt injection** | User input tricks the LLM into ignoring instructions | Regex sanitizer strips or rejects known injection patterns |
| **Unauthorized access** | Anyone on the network can use your OpenClaw instance | Bearer token auth on every request (constant-time comparison) |
| **Data exfiltration** | Skills phone home to attacker-controlled servers | DNS-level egress filtering — only allowlisted domains resolve |
| **No audit trail** | You can't tell what happened or when | Every security event logged to append-only JSON Lines |

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │           Docker (internal network)     │
  User request      │                                         │
 ──────────────►    │  ┌───────────┐      ┌───────────────┐   │
                    │  │   Proxy   │─────►│   OpenClaw    │   │
 ◄──────────────    │  │  (auth +  │      │ (unmodified)  │   │
  Response          │  │ sanitize) │      └──────┬────────┘   │
                    │  └───────────┘             │            │
                    │                            │ DNS        │
                    │                    ┌───────▼────────┐   │
                    │                    │  CoreDNS       │   │
                    │                    │  (egress       │   │
                    │                    │   allowlist)   │   │
                    │                    └────────────────┘   │
                    └─────────────────────────────────────────┘

  Offline (pre-deploy):
  ┌──────────┐     ┌─────────────┐     ┌──────────────┐
  │  Skill   │────►│   Scanner   │────►│  Quarantine  │
  │  file    │     │ (tree-sitter│     │  (SQLite DB) │
  └──────────┘     │  AST rules) │     └──────────────┘
                   └─────────────┘
```

**Key principle**: OpenClaw itself is never modified. The security stack operates as a reverse proxy in front and a DNS filter underneath.

## What Gets Scanned

The scanner uses [tree-sitter](https://tree-sitter.github.io/) to parse JavaScript/TypeScript into an AST, then walks the tree looking for:

- **Dangerous APIs** — dynamic code execution, child process spawning, dangerous constructors
- **Network exfiltration** — outbound HTTP calls via fetch, XMLHttpRequest, axios, or Node http/https modules (with domain allowlisting)
- **Filesystem abuse** — file writes, deletes, and recursive removes (flags absolute path writes and all delete operations)

Skills that fail scanning are quarantined. An admin can force-override with explicit acknowledgment, which is logged.

## Quick Start

### Prerequisites
- Docker >= 20.10 (or Podman with `podman-compose` — works as a drop-in replacement)
- Docker Compose >= 2.0
- An OpenAI or Anthropic account (API key or OAuth login)

### Deploy

```bash
git clone https://github.com/your-org/openclaw-secure-stack.git
cd openclaw-secure-stack
./install.sh
```

The installer will:
1. Detect your container runtime (Docker or Podman)
2. Generate a cryptographically random API token
3. Create `.env` from `.env.example`
4. Generate the DNS zone file from `config/egress-allowlist.conf`
5. Prompt you to configure LLM authentication (API key or OAuth)
6. Run `openclaw onboard` to configure the gateway
7. Build and start all containers
8. Wait for the gateway health check to pass

### LLM Authentication

The installer will ask you to choose:

- **API key** — paste an OpenAI or Anthropic API key (stored in `.env` and passed to OpenClaw)
- **OAuth** — interactive browser login via `openclaw onboard` (credentials persist in a Docker volume)

### Verify

```bash
# Health check (no auth required)
curl http://localhost:8080/health

# Chat request (requires token)
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $(sed -n 's/^OPENCLAW_TOKEN=//p' .env)" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

### Scan a Skill

```bash
# Scan a skill file
uv run python -m src.scanner.cli scan path/to/skill.js

# Scan and auto-quarantine if findings detected
uv run python -m src.scanner.cli scan --quarantine path/to/skill.js

# List quarantined skills
uv run python -m src.scanner.cli quarantine list

# Override quarantine (requires explicit acknowledgment)
uv run python -m src.scanner.cli quarantine override skill-name \
    --ack "I accept the risk" --user admin
```

## Configuration

### `config/egress-allowlist.conf`
One domain per line. Only these domains will resolve inside the Docker network. Everything else returns NXDOMAIN. After editing, re-run `./install.sh` to regenerate the DNS zone file.

```
api.openai.com
api.anthropic.com
```

### `config/scanner-rules.json`
Defines what the skill scanner looks for. Each rule has an ID, severity, and list of string patterns to match.

### `config/prompt-rules.json`
Regex rules for prompt injection detection. Each rule specifies a pattern and an action (`strip` removes the match, `reject` blocks the entire request).

### `.env`
Generated by `install.sh`. Contains:
- `OPENCLAW_TOKEN` — API authentication token (also used as the gateway token)
- `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` — LLM provider credentials
- `PROXY_PORT` — port the proxy listens on (default 8080)
- `OPENCLAW_IMAGE` — upstream OpenClaw Docker image

### Generated files

- `config/allowlist.db` — CoreDNS zone file generated from `egress-allowlist.conf` by `install.sh`. Do not edit directly.

## Security Hardening

All containers run with:
- **Read-only filesystem** — no writes except to mounted volumes
- **Dropped capabilities** — `cap_drop: ALL`
- **Non-root user** — UID 65534 (nobody)
- **No new privileges** — `security_opt: no-new-privileges`
- **Internal network** — no direct external access from containers
- **DNS filtering** — CoreDNS sidecar resolves only allowlisted domains
- **Distroless images** — CoreDNS uses the upstream scratch-based image; proxy uses a stripped Python runtime

## Development

```bash
# Install dependencies
uv sync

# Run tests (112 tests)
uv run pytest tests/ -q

# Lint
uv run ruff check src/ tests/

# Run proxy locally (dev mode)
uv run uvicorn src.proxy.app:create_app --factory --reload
```

## Project Structure

```
src/
├── proxy/           # Reverse proxy + auth middleware
├── scanner/         # Skill scanner + AST rules + CLI
├── quarantine/      # SQLite-backed quarantine system
├── sanitizer/       # Prompt injection detection
├── audit/           # JSON Lines audit logger
└── models.py        # Shared Pydantic data models

config/              # Scanner rules, prompt rules, egress allowlist
docker/              # CoreDNS egress sidecar
tests/               # Unit (70%) + integration (20%) + security (10%)
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
