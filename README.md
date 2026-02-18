# OpenClaw Secure Stack

**Version 1.1.0** | [Changelog](CHANGELOG.md)

A hardened deployment wrapper that makes OpenClaw safe to self-host. Wraps an unmodified OpenClaw instance with authentication, skill scanning, prompt injection mitigation, pre-execution governance, webhook integrations, network isolation, and full audit logging — without changing a single line of OpenClaw code.

## Why This Exists

OpenClaw is a powerful AI agent that can install and run third-party "skills" (JavaScript/TypeScript plugins). Running it on your infrastructure introduces real risks:

| Risk | What could happen | How we stop it |
|------|-------------------|----------------|
| **Malicious skills** | A skill runs dynamic code, spawns child processes, or exfiltrates data | AST-based scanner detects dangerous patterns before skills execute |
| **Prompt injection** | User input tricks the LLM into ignoring instructions | Regex sanitizer strips or rejects known injection patterns |
| **Indirect injection** | Tool results contain hidden instructions that hijack the agent | Plugin hook scans tool output before it enters agent context |
| **Unauthorized access** | Anyone on the network can use your OpenClaw instance | Bearer token auth on every request (constant-time comparison) |
| **Data exfiltration** | Skills phone home to attacker-controlled servers | DNS allowlisting blocks outbound traffic to non-approved domains |
| **Uncontrolled tool execution** | LLM executes dangerous tools without approval | Pre-execution governance with policy validation and human-in-the-loop approval |
| **Webhook abuse** | Attackers flood or spoof Telegram/WhatsApp endpoints | HMAC signature verification, replay protection, rate limiting, body-size limits |
| **No audit trail** | You can't tell what happened or when | Every security event logged to append-only JSON Lines |

## Architecture

```
                    ┌──────────────────────────────────────────────────────┐
                    │              Docker (internal network)               │
  User request      │                                                      │
 ──────────────►    │  ┌────────────────┐        ┌───────────────────┐     │
                    │  │     Proxy      │───────►│     OpenClaw      │     │
 ◄──────────────    │  │  (auth, gov,   │        │   (unmodified)    │     │
  Response          │  │  sanitize,     │        │                   │     │
                    │  │  audit)        │        │ ┌───────────────┐ │     │
                    │  └──┬─────────────┘        │ │ prompt-guard  │ │     │
                    │     │                      │ │ plugin (TS)   │ │     │
  Telegram ────────►│     │  /webhook/telegram   │ └───────────────┘ │     │
  WhatsApp ────────►│     │  /webhook/whatsapp   └─────────┬─────────┘     │
                    │     │                                │ DNS           │
                    │     │  ┌──────────┐          ┌───────▼────────┐      │
                    │     │  │  Caddy   │          │   CoreDNS      │      │
                    │     │  │  (HTTPS) │          │ (DNS allowlist)│      │
                    │     │  └──────────┘          └────────────────┘      │
                    └─────┼───────────────────────────────────────────────-┘
                          │
  Offline (pre-deploy):   │
  ┌──────────┐     ┌──────▼──────┐     ┌──────────────┐
  │  Skill   │────►│   Scanner   │────►│  Quarantine  │
  │  file    │     │ (tree-sitter│     │  (SQLite DB) │
  └──────────┘     │  AST rules) │     └──────────────┘
                   └─────────────┘
```

**Key principle**: OpenClaw itself is never modified. The security stack operates as a reverse proxy in front with prompt sanitization, auth, governance, and audit logging.

## How It Works

### Main Proxy Pipeline

Every API request passes through a multi-stage security pipeline before reaching OpenClaw:

```
Request ──► Auth Middleware ──► Governance ──► Sanitizer ──► OpenClaw
                                                               │
Response ◄── Audit Log ◄── Response Scanner ◄──────────────────┘
```

1. **Auth Middleware** (`src/proxy/auth_middleware.py`) — Validates `Authorization: Bearer <token>` using constant-time comparison. Public paths (`/health`) and registered webhook paths (which use their own HMAC auth) are exempt. Returns 401/403 on failure.

2. **Governance Evaluation** (`src/governance/middleware.py`) — For requests containing tool calls, classifies intent, generates an execution plan, validates against configurable policies, and decides: ALLOW, BLOCK, or REQUIRE_APPROVAL. High-risk operations (file writes, code execution, system commands) can require human approval before proceeding.

3. **Prompt Sanitizer** (`src/sanitizer/sanitizer.py`) — Scans request body for prompt injection patterns. Depending on the rule, either strips the offending text (cleaning it) or rejects the entire request with HTTP 400.

4. **Forward to OpenClaw** — The sanitized, governance-approved request is forwarded via `httpx` to the upstream OpenClaw instance. Streaming (SSE) is supported with a 5-minute timeout.

5. **Response Scanner** — Scans OpenClaw's response for indirect injection patterns (e.g., hidden instructions embedded in tool results). Findings are logged as audit events and flagged via the `X-Prompt-Guard` header.

6. **Audit Logger** (`src/audit/logger.py`) — Every security decision is recorded as an append-only JSON Lines event: auth success/failure, injection detections, governance decisions, webhook events, and more.

### Webhook Pipeline

Telegram and WhatsApp messages go through a dedicated relay pipeline that mirrors the main proxy's security stages:

```
Telegram/WhatsApp ──► Signature Check ──► Rate Limit ──► Replay Protection
                                                              │
      Platform Reply ◄── Audit ◄── Response Scan ◄── Forward ◄── Governance ◄── Sanitize ◄── Size Check ◄──┘
```

1. **Signature Verification** — Telegram: secret token header. WhatsApp: HMAC-SHA256 of request body. Invalid signatures are rejected immediately (401).
2. **Rate Limiting** — Per-IP sliding window (default 60 requests/minute). Excess requests return 429.
3. **Replay Protection** — Telegram: update_id deduplication. WhatsApp: timestamp window (default 5 minutes). Replayed messages return 409.
4. **Body Size Check** — Raw body size validated before JSON parsing to prevent OOM from oversized payloads (10MB limit, returns 413).
5. **Sanitization** — Same prompt injection scanner as the main pipeline.
6. **Governance** — Evaluates the message against governance policies. BLOCK returns 403, REQUIRE_APPROVAL returns 202.
7. **Quarantine** — Checks if the referenced skill (if any) is quarantined.
8. **Forward & Response Scan** — Translates to OpenAI-format request, forwards to OpenClaw, scans response.
9. **Platform Reply** — Sends the response back via the Telegram/WhatsApp API.

### Plugin Hook System

**⚠️ Essential Component**: The `prompt-guard` plugin is **automatically installed** by `install.sh` and is **required** for protection against indirect prompt injection attacks.

The TypeScript plugin (`plugins/prompt-guard/index.ts`) runs inside OpenClaw itself as a defense-in-depth layer:

- **`tool_result_persist` hook** — Scans tool results (web pages, API responses, files) for indirect injection patterns before they enter the agent's context window. Matching patterns are stripped or flagged based on rules in `config/indirect-injection-rules.json`.
- **`before_tool_call` hook** — Verifies that governance headers (`x-governance-plan-id`, `x-governance-token`) are present before allowing high-risk tool calls (exec, shell, file_write). Falls back to local quarantine list enforcement.

**Why it's essential**: The proxy can only see direct user input. When OpenClaw autonomously calls tools (web search, file read), the plugin is the only layer that can intercept malicious instructions embedded in those results.

### Offline Scanning Pipeline

Skills are scanned before they execute using tree-sitter AST analysis:

1. **AST Parsing** — tree-sitter parses JavaScript/TypeScript into a syntax tree
2. **Rule Walking** — AST walker rules detect dangerous APIs (eval, child_process), network exfiltration (fetch, http modules), and filesystem abuse (writeFile, rmSync)
3. **Quarantine** — Skills with findings are quarantined in SQLite. Admins can override with explicit acknowledgment (logged for audit).
4. **Pin Verification** — Skills can be pinned by SHA-256 hash. Any modification invalidates the pin and triggers re-scanning.

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

## Production Deployment (Hybrid Architecture)

For production deployments on Ubuntu 24.04 LTS servers, use the **hybrid architecture**:
- **OpenClaw Gateway**: Native (systemd) for better OAuth support and plugin performance
- **Security Proxy**: Docker container for isolation and easy updates
- **Optional Cloudflare Tunnel**: Public HTTPS access without port forwarding

### Why Hybrid?

- ✅ **Best of both worlds:** Native OpenClaw for OAuth/plugins + isolated Docker proxy
- ✅ **Stable releases:** Uses Git tags instead of bleeding-edge main branch
- ✅ **One-click install:** Automated setup including optional Cloudflare Tunnel
- ✅ **Production-ready:** Systemd services, health checks, audit logging

### Quick Start (Hybrid)

```bash
# 1. Sync repository to server
rsync -avz --exclude='.git' --exclude='.venv' --exclude='node_modules' \
  openclaw-secure-stack/ user@server:/tmp/openclaw-secure-stack/

# 2. Run one-click installer (includes optional Cloudflare Tunnel setup)
ssh -t user@server \
  "cd /tmp/openclaw-secure-stack && sudo bash deploy/hybrid/install-hybrid.sh"
```

The hybrid installer will:
1. **Ask if you have a domain** (sets up Cloudflare Tunnel if yes)
2. Install Docker, Node.js 22, pnpm
3. Clone OpenClaw (latest stable release)
4. Run OpenAI OAuth authentication (interactive browser login)
5. Build prompt-guard plugin
6. Deploy Docker proxy container
7. Start services and verify health

### Architecture (Hybrid)

```
Internet → Cloudflare Edge (optional) → Proxy (Docker, :8080) → OpenClaw (systemd, :3000) → LLM APIs
```

**Key components:**
- OpenClaw runs as systemd service (native for best compatibility)
- Proxy runs in Docker container (isolated security layer)
- Both use localhost communication (no network exposure)
- Cloudflare Tunnel optional (public access without port forwarding)

### Documentation

- **[Cloudflare Tunnel Setup Guide](docs/openclaw-cloudflare-tunnel-setup.md)** — comprehensive installation guide
- **[Quick Reference](docs/openclaw-quick-reference.md)** — command cheatsheet for operations
- **[Hybrid Deployment README](deploy/hybrid/README.md)** — detailed installer documentation

### Post-Installation (Hybrid)

**Check status:**
```bash
sudo systemctl status openclaw        # Native OpenClaw
docker ps                              # Docker proxy
sudo systemctl status cloudflared      # Tunnel (if enabled)
```

**Health checks:**
```bash
curl http://localhost:3000/health      # OpenClaw
curl http://localhost:8080/health      # Proxy
curl https://yourdomain.com/health     # Public (if tunnel enabled)
```

**View logs:**
```bash
journalctl -u openclaw -f                                                     # OpenClaw
docker logs -f openclaw-proxy                                                 # Proxy
journalctl -u cloudflared -f                                                  # Tunnel
```

**Get API token:**
```bash
sudo grep OPENCLAW_TOKEN /opt/openclaw-secure-stack/.env | cut -d= -f2
```

## Configuration

### Config Files

| File | Purpose |
|------|---------|
| `config/scanner-rules.json` | Skill scanner AST rule definitions |
| `config/prompt-rules.json` | Prompt injection detection rules (strip/reject) |
| `config/indirect-injection-rules.json` | Tool-result indirect injection rules |
| `config/governance-policies.json` | Governance policy rules (action, resource, sequence, rate) |
| `config/intent-patterns.json` | Intent classifier patterns for tool call categorization |
| `config/quarantine-list.json` | Shared quarantine list for the plugin hook |
| `config/skill-pins.json` | Skill integrity pins (SHA-256 hashes) |
| `config/egress-allowlist.conf` | DNS allowlist for outbound network access |

### `.env`
Generated by `install.sh`. Contains:
- `OPENCLAW_TOKEN` — API authentication token (also used as the gateway token)
- `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` — LLM provider credentials
- `PROXY_PORT` — port the proxy listens on (default 8080)
- `CADDY_PORT` — HTTPS port for Control UI (default 8443)
- `OPENCLAW_IMAGE` — upstream OpenClaw Docker image
- `TELEGRAM_BOT_TOKEN` — Telegram bot token (optional)
- `WHATSAPP_APP_SECRET` — WhatsApp app secret for HMAC verification (optional)
- `WHATSAPP_VERIFY_TOKEN` — WhatsApp webhook verification token (optional)
- `WHATSAPP_PHONE_NUMBER_ID` — WhatsApp phone number ID for replies (optional)
- `WHATSAPP_ACCESS_TOKEN` — WhatsApp API access token (optional)
- `GOVERNANCE_ENABLED` — enable/disable governance layer (default true)
- `GOVERNANCE_SECRET` — secret key for HMAC-signed governance tokens
- `WEBHOOK_RATE_LIMIT` — max webhook requests per IP per minute (default 60)

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

# Run tests (529 tests)
uv run pytest tests/ -q

# Lint
uv run ruff check src/ tests/

# Type check
uv run mypy src/

# Run proxy locally (dev mode)
uv run uvicorn src.proxy.app:create_app_from_env --factory --reload
```

## Project Structure

```
src/
├── proxy/               # Reverse proxy + auth middleware
│   ├── app.py               # FastAPI app factory, webhook registration, catch-all proxy
│   ├── auth_middleware.py    # ASGI middleware: Bearer token auth + webhook path exemptions
│   ├── governance_helpers.py # evaluate_governance, has_tool_calls, strip_governance_headers
│   └── governance_routes.py  # REST API for governance approvals and queries
├── webhook/             # Telegram & WhatsApp relay pipeline
│   ├── relay.py             # WebhookRelayPipeline (sanitize → governance → quarantine → forward)
│   ├── telegram.py          # Telegram signature verification, message extraction, reply
│   ├── whatsapp.py          # WhatsApp HMAC verification, message extraction, reply
│   ├── rate_limiter.py      # Per-IP sliding window rate limiter
│   ├── replay_protection.py # SQLite-backed replay detection (update_id / timestamp)
│   └── models.py            # WebhookMessage, WebhookResponse
├── governance/          # Pre-execution governance layer
│   ├── middleware.py        # Orchestrator for all governance components
│   ├── classifier.py        # Intent classification from tool calls
│   ├── planner.py           # Execution plan generation
│   ├── validator.py         # Policy validation engine
│   ├── approver.py          # Human-in-the-loop approval gate
│   ├── enforcer.py          # Runtime execution enforcement
│   ├── session.py           # Multi-turn session management
│   ├── store.py             # Plan storage with HMAC tokens
│   └── models.py            # GovernanceDecision, Intent, ExecutionPlan, etc.
├── scanner/             # Skill scanner + AST rules + CLI
│   ├── scanner.py           # Core engine: loads rules, scans files via tree-sitter
│   ├── cli.py               # Click CLI: scan, quarantine list/override
│   ├── trust_score.py       # Trust score computation for skills
│   └── rules/               # AST walker rules by detection category
├── quarantine/          # SQLite-backed quarantine system
│   ├── db.py                # Quarantine database layer
│   └── manager.py           # Quarantine lifecycle: quarantine, override, rescan
├── sanitizer/           # Prompt injection detection
│   └── sanitizer.py         # Regex strip/reject rules engine
├── audit/               # JSON Lines audit logger
│   └── logger.py            # Append-only security event logging (file-locked writes)
└── models.py            # Shared Pydantic data models

plugins/prompt-guard/    # OpenClaw plugin hook (TypeScript)
│   └── index.ts             # tool_result_persist + before_tool_call hooks

config/                  # Scanner rules, prompt rules, governance policies
docker/                  # CoreDNS DNS forwarder, Caddy reverse proxy
docs/                    # User and developer quickstarts
scripts/                 # Operational scripts (audit.py)
tests/
├── unit/                # Module-level tests
├── integration/         # Cross-module behavior tests
└── security/            # Adversarial and abuse-path tests
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
| 403 on tool call | Governance blocked the request | Check governance policies in `config/governance-policies.json`; approve via governance API if needed |
| 202 on webhook message | Governance requires approval | Approve the pending request via the governance approval API |
| DNS resolution fails | CoreDNS not healthy | Check `docker compose logs egress-dns`; verify `config/allowlist.db` exists |
| Certificate errors | Caddy can't issue cert | Verify domain DNS points to this host; check `docker compose logs caddy` |
| Skill quarantined unexpectedly | Scanner detected suspicious patterns | Review findings with `uv run python -m src.scanner.cli quarantine list`; override with `quarantine override` if false positive |
| Audit log not writing | Volume permissions | Check `./.local-volumes/proxy-data` mount; ensure container UID 65534 can write |
| `scripts/audit.py` exits 2 | Docker/Podman not found | Install Docker >= 20.10 or Podman |
| 429 on webhook | Rate limit exceeded | Increase `WEBHOOK_RATE_LIMIT` in `.env` or wait for window to reset |
| 413 on webhook | Request body too large | Webhook payloads are limited to 10MB |

## Maintenance / Rebuild Strategy

### When to Rebuild

- **Monthly**: Rebuild images to pick up base image security patches
- **On CVE**: When a base image CVE is published affecting `python:3.12-slim` or `coredns:1.11.1`
- **On config change**: After modifying `config/scanner-rules.json` or Dockerfile

### How to Rebuild

```bash
# Full rebuild (no cache)
docker compose build --no-cache

# Ensure local bind-mount folders exist
mkdir -p .local-volumes/{proxy-data,openclaw-data,caddy-data,caddy-config}

# Restart services
docker compose up -d
```

### Base Image Pinning

All Dockerfiles pin base images by SHA-256 digest. To update:

1. Pull the new image: `docker pull python:3.12-slim`
2. Get digest: `docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim`
3. Update the `@sha256:...` in the Dockerfile
4. Rebuild and test

## Cloudflare Tunnel Deployment

For **private server deployment with public HTTPS access** without port forwarding, you can use Cloudflare Tunnel:

### Benefits
- **No port forwarding needed** — server stays on private network
- **Automatic HTTPS** — Let's Encrypt certificates managed by Cloudflare
- **DDoS protection** — traffic routes through Cloudflare's edge network
- **Hidden server IP** — only outbound connections to Cloudflare
- **Zero trust security** — WAF, rate limiting, and access control at the edge

### Quick Start (Cloudflare Tunnel)

```bash
# 1. Add domain to Cloudflare and update nameservers
# 2. Install cloudflared on your server
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /tmp/cloudflared
sudo install -m 755 /tmp/cloudflared /usr/local/bin/cloudflared

# 3. Authenticate with Cloudflare
cloudflared tunnel login

# 4. Create tunnel
cloudflared tunnel create openclaw

# 5. Configure tunnel (see detailed guide)
# 6. Route DNS
cloudflared tunnel route dns openclaw yourdomain.com

# 7. Install as service
sudo cloudflared service install
sudo systemctl enable --now cloudflared

# 8. Deploy OpenClaw (hybrid installer auto-configures tunnel)
cd /tmp/openclaw-secure-stack
sudo bash deploy/hybrid/install-hybrid.sh
```

**Note:** The hybrid installer includes integrated Cloudflare Tunnel setup! You can also run steps 2-7 manually if you prefer, then use the installer which will detect existing tunnel configuration.

### Architecture (Cloudflare Tunnel + Hybrid)

```
User → Cloudflare Edge (HTTPS) → Tunnel (outbound-only) → Proxy (Docker) → OpenClaw (systemd) → LLM APIs
```

### Documentation

- **[Cloudflare Tunnel Setup Guide](docs/openclaw-cloudflare-tunnel-setup.md)** — comprehensive installation guide with manual + automated options
- **[Quick Reference](docs/openclaw-quick-reference.md)** — command cheatsheet for operations
- **[Hybrid Deployment README](deploy/hybrid/README.md)** — detailed installer documentation

**Recommended:** Use the hybrid installer with Cloudflare Tunnel option for best security and ease of deployment.

---

## Documentation

- [User Quick Start](docs/quickstart-user.md) — operations guide for deploying and running the stack
- [Developer Quick Start](docs/quickstart-dev.md) — contributor guide for local development and extending the codebase
- [Telegram Webhook Setup](docs/telegram-webhook-setup.md) — connect your Telegram bot with Cloudflare Tunnel
- [Cloudflare Tunnel Setup](docs/openclaw-cloudflare-tunnel-setup.md) — deploy with private server and public HTTPS
- [Quick Reference](docs/openclaw-quick-reference.md) — command cheatsheet for operations

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
