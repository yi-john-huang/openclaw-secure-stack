# OpenClaw Secure Stack

A hardened deployment wrapper that makes OpenClaw safe to self-host. Wraps an unmodified OpenClaw instance with authentication, skill scanning, prompt injection mitigation, network isolation, and full audit logging — without changing a single line of OpenClaw code.

## Why This Exists

OpenClaw is a powerful AI agent that can install and run third-party "skills" (JavaScript/TypeScript plugins). Running it on your infrastructure introduces real risks:

| Risk | What could happen | How we stop it |
|------|-------------------|----------------|
| **Malicious skills** | A skill runs dynamic code, spawns child processes, or exfiltrates data | AST-based scanner detects dangerous patterns before skills execute |
| **Prompt injection** | User input tricks the LLM into ignoring instructions | Regex sanitizer strips or rejects known injection patterns |
| **Unauthorized access** | Anyone on the network can use your OpenClaw instance | Bearer token auth on every request (constant-time comparison) |
| **Data exfiltration** | Skills phone home to attacker-controlled servers | AST-based scanner flags outbound network calls to non-allowlisted domains |
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
                    │                    │  (DNS          │   │
                    │                    │   forwarder)   │   │
                    │                    └────────────────┘   │
                    └─────────────────────────────────────────┘

  Offline (pre-deploy):
  ┌──────────┐     ┌─────────────┐     ┌──────────────┐
  │  Skill   │────►│   Scanner   │────►│  Quarantine  │
  │  file    │     │ (tree-sitter│     │  (SQLite DB) │
  └──────────┘     │  AST rules) │     └──────────────┘
                   └─────────────┘
```

**Key principle**: OpenClaw itself is never modified. The security stack operates as a reverse proxy in front with prompt sanitization, auth, and audit logging.

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
4. Prompt you to configure LLM authentication (API key or OAuth)
5. Run `openclaw onboard` to configure the gateway
6. Enable the OpenAI-compatible HTTP API (`chatCompletions` endpoint)
7. Configure trusted proxies and Control UI auth for Docker networking
8. Build and start all containers
9. Wait for the gateway health check to pass

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

### `config/scanner-rules.json`
Defines what the skill scanner looks for. Each rule has an ID, severity, and list of string patterns to match.

### `config/prompt-rules.json`
Regex rules for prompt injection detection. Each rule specifies a pattern and an action (`strip` removes the match, `reject` blocks the entire request).

### `.env`
Generated by `install.sh`. Contains:
- `OPENCLAW_TOKEN` — API authentication token (also used as the gateway token)
- `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` — LLM provider credentials
- `TELEGRAM_BOT_TOKEN` — Telegram bot token (optional, for Telegram integration)
- `PROXY_PORT` — port the proxy listens on (default 8080)
- `CADDY_PORT` — HTTPS port for Control UI (default 8443)
- `OPENCLAW_IMAGE` — upstream OpenClaw Docker image

## Security Hardening

All containers run with:
- **Read-only filesystem** — no writes except to mounted volumes
- **Dropped capabilities** — `cap_drop: ALL`
- **Non-root user** — UID 65534 (nobody)
- **No new privileges** — `security_opt: no-new-privileges`
- **Network isolation** — proxy runs on an internal-only network; only OpenClaw and the DNS forwarder have external access
- **Code scanning** — AST-based scanner flags outbound network calls to non-allowlisted domains
- **Distroless images** — CoreDNS uses the upstream scratch-based image; proxy uses a stripped Python runtime

## Development

```bash
# Install dependencies
uv sync

# Run tests (117 tests)
uv run pytest tests/ -q

# Lint
uv run ruff check src/ tests/

# Run proxy locally (dev mode)
uv run uvicorn src.proxy.app:create_app_from_env --factory --reload
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

config/              # Scanner rules, prompt rules
docker/              # CoreDNS DNS forwarder, Caddy reverse proxy
tests/               # Unit (70%) + integration (20%) + security (10%)
```

## Network Policy

### Topology

```
Host machine
├── proxy (port 8080) ─── internal network ──── openclaw (no host ports)
├── caddy (port 8443) ─── internal network ──┘
└── egress-dns (172.28.0.10) ── egress network ── openclaw
```

### Port Exposure Rules

| Service | Host Port | Internal Port | Notes |
|---------|-----------|---------------|-------|
| proxy | 8080 (configurable via `PROXY_PORT`) | 8080 | Only externally accessible API endpoint |
| caddy | 8443 (configurable via `CADDY_PORT`) | 443 | HTTPS reverse proxy for Control UI |
| openclaw | none | 3000 | Only reachable from proxy via internal network |
| egress-dns | none | 53 | Internal DNS forwarder |

### Egress Policy

Outbound network access from `openclaw` is restricted by DNS allowlisting via CoreDNS:

- Allowed domains are listed in `config/egress-allowlist.conf`
- The zone file `config/allowlist.db` is generated by `install.sh`
- To add a domain: add it to `egress-allowlist.conf` and re-run `install.sh` or regenerate the zone file
- To remove a domain: delete it from `egress-allowlist.conf` and regenerate

If you need direct access to openclaw for debugging, create a `docker-compose.override.yml`:

```yaml
services:
  openclaw:
    ports:
      - "3000:3000"
```

## Security Audit

Run the security audit script to validate the stack's security posture:

```bash
python scripts/audit.py              # Human-readable output
python scripts/audit.py --format json # Machine-parseable JSON
```

Exit codes: `0` = all checks pass, `1` = findings reported, `2` = prerequisite failure.

The audit checks: container hardening, network isolation, secret management, log integrity, skill security, and documentation completeness.

## Troubleshooting

| Symptom | Cause | Resolution |
|---------|-------|------------|
| Stack won't start | Docker not running or wrong version | Check `docker --version` >= 20.10 and Docker daemon is running |
| 401 on all requests | Token mismatch between client and proxy | Verify `Authorization: Bearer <token>` matches `OPENCLAW_TOKEN` in `.env`; restart proxy after changes |
| DNS resolution fails | CoreDNS not healthy | Check `docker compose logs egress-dns`; verify `config/allowlist.db` exists |
| Certificate errors | Caddy can't issue cert | Verify domain DNS points to this host; check `docker compose logs caddy` |
| Skill quarantined unexpectedly | Scanner detected suspicious patterns | Review findings with `uv run python -m src.scanner.cli quarantine list`; override with `quarantine override` if false positive |
| Audit log not writing | Volume permissions | Check `audit-data` volume mount; ensure container UID 65534 can write |
| `scripts/audit.py` exits 2 | Docker/Podman not found | Install Docker >= 20.10 or Podman |

## Maintenance / Rebuild Strategy

### When to Rebuild

- **Monthly**: Rebuild images to pick up base image security patches
- **On CVE**: When a base image CVE is published affecting `python:3.12-slim` or `coredns:1.11.1`
- **On config change**: After modifying `config/scanner-rules.json` or Dockerfile

### How to Rebuild

```bash
# Full rebuild (no cache)
docker compose build --no-cache

# Restart services
docker compose up -d
```

### Base Image Pinning

All Dockerfiles pin base images by SHA-256 digest. To update:

1. Pull the new image: `docker pull python:3.12-slim`
2. Get digest: `docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim`
3. Update the `@sha256:...` in the Dockerfile
4. Rebuild and test

## Documentation

- [User Quick Start](docs/quickstart-user.md) — operations guide for deploying and running the stack
- [Developer Quick Start](docs/quickstart-dev.md) — contributor guide for local development and extending the codebase

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
