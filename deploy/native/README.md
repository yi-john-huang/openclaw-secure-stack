# Native Deployment for OpenClaw Secure Stack

This directory contains native deployment artifacts for running OpenClaw Secure Stack on **Ubuntu 24.04 LTS** using systemd instead of Docker Compose.

## Quick Start

```bash
# Clone repository
git clone https://github.com/yihuang/openclaw-secure-stack.git
cd openclaw-secure-stack

# Run installer as root
sudo bash deploy/native/install-native.sh
```

## Files

| File | Purpose |
|------|---------|
| **install-native.sh** | Automated installer (11 phases: packages, users, dirs, code, onboarding, etc.) |
| **DEPLOYMENT.md** | Comprehensive deployment guide with architecture, troubleshooting, operations |
| **openclaw.service** | systemd unit for OpenClaw Node.js gateway |
| **openclaw-proxy.service** | systemd unit for Python FastAPI proxy |
| **Caddyfile.localhost** | Caddy config for localhost (self-signed TLS) |
| **Caddyfile.domain** | Caddy config for public domain (Let's Encrypt) |
| **openclaw.env.template** | Environment template for OpenClaw gateway |
| **proxy.env.template** | Environment template for proxy/governance/webhooks |
| **openclaw-backup.sh** | Daily backup script (installs to `/etc/cron.daily/`) |
| **health-check.sh** | Service health monitoring (installs to `/usr/local/bin/`) |
| **uninstall.sh** | Clean removal script |

## Architecture

```
Caddy (:443, 0.0.0.0) → Proxy (:8080, 127.0.0.1) → OpenClaw (:3000, 127.0.0.1) → LLM APIs
```

**Key differences from Docker:**
- Services managed by systemd instead of Docker Compose
- Localhost binding + UFW firewall instead of Docker networks
- systemd sandboxing instead of container isolation
- No DNS egress filtering (user opted out)

## Target Hardware

**Tested on:** 2010 Mac Mini (2 CPU / 4 threads, 8GB RAM, 120GB SSD + 500GB HDD)

**Storage layout:**
- SSD: OS, apps, SQLite databases
- HDD: Audit logs, backups

## Prerequisites

- Ubuntu 24.04 LTS Server (headless recommended)
- Root access
- Internet connectivity
- LLM API key (OpenAI or Anthropic)
- Secondary storage mounted at `/mnt/data` (or custom path)

## Installation Steps

1. **Prerequisites check** — Verifies Ubuntu 24.04, root, internet
2. **System packages** — Node.js 22, Python 3.12, Caddy, uv, SQLite
3. **System users** — Creates `openclaw` and `ocproxy` service accounts
4. **Directory structure** — `/opt/`, `/var/lib/`, `/etc/`, `/mnt/data/`
5. **Deploy code** — Clones repos, installs dependencies
6. **OpenClaw onboarding** — Interactive LLM authentication
7. **Generate env files** — Creates secrets, tokens
8. **Install systemd units** — Copies service files, Caddyfile
9. **Set permissions** — Least-privilege ownership model
10. **Firewall** — UFW allow SSH/80/443, deny rest
11. **Start & verify** — Health checks, diagnostics

## Post-Installation

**Check status:**
```bash
systemctl status openclaw openclaw-proxy caddy
```

**Run health check:**
```bash
/usr/local/bin/openclaw-health-check
```

**View logs:**
```bash
journalctl -u openclaw -f
journalctl -u openclaw-proxy -f
```

**Test API:**
```bash
curl -X POST https://localhost/v1/chat/completions \
  -H "Authorization: Bearer $(grep OPENCLAW_TOKEN /etc/openclaw-secure-stack/proxy.env | cut -d= -f2)" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Operations

**Restart services:**
```bash
sudo systemctl restart openclaw openclaw-proxy
```

**Edit configuration:**
```bash
sudo nano /etc/openclaw-secure-stack/openclaw.env  # OpenClaw settings
sudo nano /etc/openclaw-secure-stack/proxy.env     # Proxy/governance/webhooks
sudo systemctl restart openclaw openclaw-proxy
```

**Update code:**
```bash
cd /opt/openclaw-secure-stack
sudo git pull origin master
sudo systemctl restart openclaw-proxy
```

**Backups:**
- Automatic: Daily at `/etc/cron.daily/openclaw-backup` → `/mnt/data/backups/`
- Manual: `sudo /etc/cron.daily/openclaw-backup`
- Retention: 30 days

## Uninstallation

```bash
sudo /opt/openclaw-secure-stack/deploy/native/uninstall.sh
```

## Documentation

See **[DEPLOYMENT.md](./DEPLOYMENT.md)** for:
- Detailed architecture diagrams
- Storage layout specifications
- Security model explanation
- Comprehensive troubleshooting guide
- Backup/restore procedures
- Update procedures
- Docker vs Native comparison

## Support

**Issues:** [github.com/yihuang/openclaw-secure-stack/issues](https://github.com/yihuang/openclaw-secure-stack/issues)

**Logs to attach:**
```bash
sudo journalctl -u openclaw -u openclaw-proxy -u caddy --since "30 min ago" > /tmp/openclaw-logs.txt
/usr/local/bin/openclaw-health-check
```
