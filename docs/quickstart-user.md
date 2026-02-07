# User Quick Start

Operations guide for deploying and running OpenClaw Secure Stack.

## What You Get After Install

Running `./install.sh` starts four containers:

| Container | Role | Port |
|-----------|------|------|
| **proxy** | Reverse proxy — authenticates requests, sanitizes prompts, evaluates governance, handles webhooks, forwards to OpenClaw | `${PROXY_PORT:-8080}` on the host |
| **openclaw** | OpenClaw gateway — serves WebSocket + HTTP API, runs the plugin hook | `3000` on the host |
| **caddy** | HTTPS reverse proxy for the Control UI (self-signed cert for localhost) | `${CADDY_PORT:-8443}` on the host |
| **egress-dns** | CoreDNS sidecar — forwards DNS queries to public resolvers | 172.28.0.10 (internal) |

All containers run read-only, as non-root, with dropped capabilities.

## Your API Token

The installer generates a random token and stores it in `.env` as `OPENCLAW_TOKEN`. To retrieve it:

```bash
grep OPENCLAW_TOKEN .env
```

Include it in every request:

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Common Operations

### Stop / Start / Restart

```bash
docker compose down          # stop all containers
docker compose up -d         # start in background
docker compose restart       # restart all
docker compose restart proxy # restart just the proxy
```

### View Logs

```bash
docker compose logs -f          # all containers, follow
docker compose logs -f proxy    # proxy only
docker compose logs openclaw    # openclaw output
```

## Configuration Changes

### Changing LLM Provider or API Key

Edit `.env` and set the appropriate key:

```bash
# For OpenAI
OPENAI_API_KEY=sk-...

# For Anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

Then restart:

```bash
docker compose restart
```

### Changing the Proxy Port

Edit `.env`:

```bash
PROXY_PORT=9090
```

Then restart:

```bash
docker compose down && docker compose up -d
```

### Using a Custom DNS Server

By default, the stack forwards DNS queries to Google Public DNS (`8.8.8.8`). To use a filtering DNS provider that blocks malicious or unwanted domains, edit `docker/egress/Corefile`:

```
. {
    forward . <your-dns-server-ip>
    log
    errors
}
```

Common filtering DNS options:

| Provider | IPs | What it blocks |
|----------|-----|----------------|
| Cloudflare Family | `1.1.1.3 1.0.0.3` | Malware + adult content |
| Cloudflare Malware-only | `1.1.1.2 1.0.0.2` | Malware |
| NextDNS | `45.90.28.0 45.90.30.0` | Customizable via dashboard |
| Pi-hole / AdGuard Home | Your server IP | Self-hosted, fully customizable |

Then rebuild the DNS container:

```bash
docker compose up -d --build egress-dns
```

## Control UI

Access the OpenClaw Control UI dashboard at:

```
https://localhost:8443/?token=YOUR_OPENCLAW_TOKEN
```

Your browser will show a certificate warning (self-signed cert) — this is expected for localhost. Accept it to proceed.

Get your token with: `grep OPENCLAW_TOKEN .env`

## Telegram Integration

To connect OpenClaw to Telegram via webhooks (recommended for full security pipeline):

1. Create a bot with [@BotFather](https://t.me/BotFather) on Telegram
2. Add the bot token to `.env`:
   ```
   TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
   ```
3. Restart: `docker compose restart proxy`
4. Set up a public URL for the webhook endpoint:
   - **For local dev/testing**: Use Cloudflare Tunnel (see [Telegram Webhook Setup Guide](telegram-webhook-setup.md))
   - **For production**: Configure your domain to point to the proxy's public IP

The proxy exposes a `/webhook/telegram` endpoint. Messages sent to your bot are relayed through the secure proxy pipeline (sanitization, governance, response scanning) before reaching OpenClaw.

📖 **Detailed setup guide**: [docs/telegram-webhook-setup.md](telegram-webhook-setup.md)

## WhatsApp Integration

To connect OpenClaw to WhatsApp:

1. Set up a WhatsApp Business API account and configure a webhook
2. Add the credentials to `.env`:
   ```
   WHATSAPP_VERIFY_TOKEN=your-verify-token
   WHATSAPP_APP_SECRET=your-app-secret
   ```
3. Point the WhatsApp webhook URL to `https://your-domain/webhook/whatsapp`
4. Restart: `docker compose restart proxy`

The proxy verifies incoming webhooks via HMAC signature (`X-Hub-Signature-256` header) using `WHATSAPP_APP_SECRET`. GET requests to `/webhook/whatsapp` handle the WhatsApp verification challenge. All messages pass through the same secure pipeline as Telegram (sanitization, governance, response scanning).

## Governance Layer

The governance layer evaluates tool-call requests before they reach OpenClaw. It applies configurable policies to classify, validate, and optionally require human approval for high-risk operations.

### How It Works

1. Proxy intercepts requests containing tool calls
2. Intent classifier categorizes the tool call (file read/write, network, code execution, system)
3. Policy validator checks against rules in `config/governance-policies.json`
4. Low-risk operations proceed automatically; high-risk operations require human approval
5. Approved plans receive HMAC-signed tokens for execution

### Governance Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/governance/plans` | GET | List pending plans |
| `/governance/plans/{id}/approve` | POST | Approve a pending plan |
| `/governance/plans/{id}/reject` | POST | Reject a pending plan |

### Configuring Policies

Edit `config/governance-policies.json` to adjust which operations require approval. Policy types include:
- **action policies** — allow/block by tool-call type
- **resource policies** — restrict access to specific file paths or URLs
- **sequence policies** — detect suspicious multi-step patterns
- **rate policies** — limit operation frequency per session

## Reading the Audit Log

The proxy writes security events as JSON Lines to the audit log inside the container. To view:

```bash
docker compose exec proxy cat /var/log/audit/audit.jsonl
```

Each line is a JSON object with fields: `timestamp`, `event_type`, `source_ip`, `action`, `result`, `risk_level`, and `details`.

Event types include:
- `auth_success` / `auth_failure` — authentication attempts
- `prompt_injection` — detected prompt injection patterns
- `skill_scan` / `skill_quarantine` / `skill_override` — scanner events
- `governance_eval` / `governance_approve` / `governance_reject` — governance decisions
- `webhook_relay` — webhook message processing (Telegram/WhatsApp)

## What Blocked Requests Look Like

| Scenario | HTTP Status | Meaning |
|----------|-------------|---------|
| Missing or invalid token | 401 | Authentication failed |
| Valid token but wrong permissions | 403 | Access denied |
| Prompt injection detected (reject rule) | 400 | Request blocked by sanitizer |
| Governance blocks a tool call | 403 | Blocked by governance policy |
| Governance requires approval | 202 | Pending human approval (includes approval ID) |
| Webhook rate limit exceeded | 429 | Too many messages from this sender |
| Webhook body too large | 413 | Request body exceeds 10 MB limit |
| Webhook replay detected | 409 | Duplicate message (nonce already seen) |
| Suspicious network call in skill | Scanner finding | Flagged by AST-based code scanner |

## Re-running the Installer

Running `./install.sh` again is safe. It will:
- Preserve your existing `.env` (prompts before overwriting)
- Configure the OpenClaw gateway (HTTP API, trusted proxies, Control UI auth)
- Rebuild and restart containers

## Troubleshooting

1. **Health check fails**: Run `curl http://localhost:8080/health` — if it times out, check `docker compose ps` for container status.
2. **401 on every request**: Verify your token matches `OPENCLAW_TOKEN` in `.env`. The `Authorization` header must be `Bearer <token>`.
3. **LLM calls fail**: Check that the correct API key is set in `.env`. Verify DNS is working with `docker compose exec openclaw nslookup api.openai.com`.
4. **Container won't start**: Run `docker compose logs` to see error output. Common cause: port conflict on `PROXY_PORT`.
5. **Skills blocked unexpectedly**: Check scanner findings with `uv run python -m src.scanner.cli scan <skill-path>`. Review `config/scanner-rules.json` for rule definitions.
6. **Control UI "pairing required"**: Make sure you access via the tokenized URL: `https://localhost:8443/?token=YOUR_TOKEN`. The installer configures `allowInsecureAuth` to bypass device pairing in Docker.
7. **Telegram bot not responding**: Check `docker compose logs proxy | grep telegram`. Verify `TELEGRAM_BOT_TOKEN` is set in `.env`.
8. **WhatsApp webhook 403**: Verify `WHATSAPP_APP_SECRET` is set in `.env` and the `X-Hub-Signature-256` header is being sent by WhatsApp.
9. **Governance blocking everything**: Review `config/governance-policies.json`. Policies may be too restrictive. Check pending plans via `GET /governance/plans`.
10. **Webhook 413 errors**: The request body exceeds the 10 MB limit. This is a hard limit to prevent memory exhaustion.
